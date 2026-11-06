// Package broker serves the read sandbox's only ways to reach data (ADR
// 0019): Unix sockets bound read-only into the sandbox, each forwarding reads
// of one source and nothing else.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// Limits on one broker call.
const (
	MaxRequest  = 16 << 10
	MaxResponse = 16 << 20
	CallTimeout = 60 * time.Second
)

// CallHeader carries the sandbox run's id into the audit record.
const CallHeader = "X-Advisor-Call"

// DefaultDir is where the sockets and client commands live on a node.
const DefaultDir = "/run/cube-advisor-agent/broker"

// DefaultPrometheus is CubeCOS's Prometheus (3.1.10 and 3.2.0).
const DefaultPrometheus = "http://127.0.0.1:9091/prometheus"

// Server serves the brokers.
type Server struct {
	Dir        string
	Prometheus string // base URL, no trailing slash
	Audit      toolplane.Auditor
	// CephTable returns Ceph's command table; CephRun runs `ceph args...`.
	CephTable func(ctx context.Context) ([]CephCommand, error)
	CephRun   func(ctx context.Context, args []string) (stdout, stderr []byte, err error)
	// HostRun runs the host broker's fixed commands; nil means LocalHostRun.
	HostRun func(ctx context.Context, name string, args []string) (stdout, stderr []byte, err error)
	Client  *http.Client

	mu      sync.Mutex
	table   []CephCommand
	tableAt time.Time
}

// Start creates the directory, the client commands and the sockets, and
// serves until ctx ends.
func (s *Server) Start(ctx context.Context) error {
	bin := filepath.Join(s.Dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		return err
	}
	for name, body := range clients(s.Dir) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			return err
		}
	}
	for name, h := range map[string]http.Handler{"prom.sock": http.HandlerFunc(s.prom), "ceph.sock": http.HandlerFunc(s.ceph),
		"host.sock": http.HandlerFunc(s.host)} {
		path := filepath.Join(s.Dir, name)
		_ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		if err := os.Chmod(path, 0o666); err != nil {
			return err
		}
		srv := &http.Server{Handler: http.MaxBytesHandler(h, MaxRequest), ReadHeaderTimeout: 10 * time.Second}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		go func() {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("broker %s: %v", name, err)
			}
		}()
	}
	return nil
}

func (s *Server) record(r *http.Request, tool string, args map[string]string, allowed bool, reason string, started time.Time, n int) {
	if s.Audit == nil {
		return
	}
	if id := r.Header.Get(CallHeader); id != "" {
		args["call"] = id
	}
	s.Audit.RecordToolCall(toolplane.ToolCall{Tool: tool, Args: args, Allowed: allowed, Reason: reason,
		At: started.UTC(), Duration: time.Since(started), Bytes: n})
}

// promDenied are Prometheus paths that write or expose configuration.
var promDenied = []string{"/api/v1/admin/", "/api/v1/write", "/api/v1/otlp/", "/api/v1/status/config", "/-/"}

func (s *Server) prom(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	args := map[string]string{"path": r.URL.Path, "query": r.URL.RawQuery}
	refuse := func(code int, why string) {
		s.record(r, "broker:prom", args, false, why, started, 0)
		http.Error(w, why, code)
	}
	if r.Method != http.MethodGet {
		refuse(http.StatusMethodNotAllowed, "only GET is forwarded")
		return
	}
	p := r.URL.Path
	if !strings.HasPrefix(p, "/api/v1/") || strings.Contains(p, "..") {
		refuse(http.StatusForbidden, "only /api/v1/ paths are forwarded")
		return
	}
	for _, d := range promDenied {
		if strings.HasPrefix(p, d) || p == strings.TrimSuffix(d, "/") {
			refuse(http.StatusForbidden, p+" writes or exposes configuration")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), CallTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.Prometheus+p+"?"+r.URL.RawQuery, nil)
	c := s.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		refuse(http.StatusBadGateway, "prometheus: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, truncated := readCapped(resp.Body)
	reason := ""
	if truncated {
		reason = fmt.Sprintf("answer cut at %d bytes", MaxResponse)
	}
	s.record(r, "broker:prom", args, true, reason, started, len(body))
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
	if truncated {
		fmt.Fprintf(w, "\n[broker: answer cut at %d bytes]\n", MaxResponse)
	}
}

func (s *Server) ceph(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var in struct {
		Args []string `json:"args"`
	}
	args := map[string]string{}
	refuse := func(code int, why string) {
		s.record(r, "broker:ceph", args, false, why, started, 0)
		http.Error(w, why, code)
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&in) != nil {
		refuse(http.StatusBadRequest, `POST {"args":[...]}`)
		return
	}
	args["args"] = strings.Join(in.Args, " ")
	ctx, cancel := context.WithTimeout(r.Context(), CallTimeout)
	defer cancel()
	table, err := s.cephTable(ctx)
	if err != nil {
		refuse(http.StatusBadGateway, "reading Ceph's command table: "+err.Error())
		return
	}
	if err := CheckCephArgs(table, in.Args); err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	out, errOut, err := s.CephRun(ctx, in.Args)
	if len(out) > MaxResponse {
		out = append(out[:MaxResponse], fmt.Sprintf("\n[broker: answer cut at %d bytes]\n", MaxResponse)...)
	}
	reason := ""
	code := http.StatusOK
	if err != nil {
		reason, code = err.Error(), http.StatusBadGateway
		out = append(out, errOut...)
	}
	s.record(r, "broker:ceph", args, true, reason, started, len(out))
	w.WriteHeader(code)
	_, _ = w.Write(out)
}

// cephTable caches Ceph's command table for an hour.
func (s *Server) cephTable(ctx context.Context) ([]CephCommand, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.table != nil && time.Since(s.tableAt) < time.Hour {
		return s.table, nil
	}
	t, err := s.CephTable(ctx)
	if err != nil {
		return nil, err
	}
	s.table, s.tableAt = t, time.Now()
	return t, nil
}

func readCapped(r io.Reader) ([]byte, bool) {
	b, _ := io.ReadAll(io.LimitReader(r, MaxResponse+1))
	if len(b) > MaxResponse {
		return b[:MaxResponse], true
	}
	return b, false
}

// cephDescriptionsScript prints the monitor's and manager's command tables
// as one JSON object, through librados (the ceph CLI does not expose them).
const cephDescriptionsScript = `import json, rados
r = rados.Rados(conffile="/etc/ceph/ceph.conf"); r.connect(timeout=20)
out = {}
for name, call in (("mon", r.mon_command), ("mgr", r.mgr_command)):
    ret, buf, err = call(json.dumps({"prefix": "get_command_descriptions"}), b"", timeout=20)
    if ret != 0:
        raise SystemExit("%s: %s" % (name, err))
    for k, v in json.loads(buf).items():
        out[name + ":" + k] = v
r.shutdown()
print(json.dumps(out))`

// LocalCephTable reads the node's Ceph command tables with python3-rados.
func LocalCephTable(ctx context.Context) ([]CephCommand, error) {
	out, err := exec.CommandContext(ctx, "python3", "-c", cephDescriptionsScript).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%v: %s", err, bytes.TrimSpace(ee.Stderr))
		}
		return nil, err
	}
	return ParseCephDescriptions(out)
}

// LocalCephRun runs the ceph CLI without a shell.
func LocalCephRun(ctx context.Context, args []string) ([]byte, []byte, error) {
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, "ceph", args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// clients are the commands bound into the sandbox's PATH.
func clients(dir string) map[string]string {
	prom := `#!/bin/sh
# prom: read-only Prometheus through the agent's broker (ADR 0019).
#   prom query EXPR [TIME]          instant query
#   prom range EXPR [SPAN] [STEP]   range query over the last SPAN (default 1h; e.g. 30d), STEP seconds (default 300)
#   prom series MATCH               series matching a selector
#   prom labels                     label names
#   prom status NAME                runtimeinfo | buildinfo | tsdb | flags
#   prom get PATH?QUERY             any other read under /api/v1/
S=` + dir + `/prom.sock
H="` + CallHeader + `: ${ADVISOR_CALL_ID:-}"
c() { curl -sS --unix-socket "$S" -H "$H" "$@"; }
secs() { case "$1" in *d) echo $(( ${1%d} * 86400 ));; *h) echo $(( ${1%h} * 3600 ));; *m) echo $(( ${1%m} * 60 ));; *) echo "$1";; esac; }
case "$1" in
  query) c -G http://broker/api/v1/query --data-urlencode "query=$2" ${3:+--data-urlencode "time=$3"} ;;
  range) end=$(date +%s); start=$(( end - $(secs "${3:-1h}") ))
         c -G http://broker/api/v1/query_range --data-urlencode "query=$2" --data-urlencode "start=$start" --data-urlencode "end=$end" --data-urlencode "step=${4:-300}" ;;
  series) c -G http://broker/api/v1/series --data-urlencode "match[]=$2" ;;
  labels) c http://broker/api/v1/labels ;;
  status) c "http://broker/api/v1/status/$2" ;;
  get) c "http://broker$2" ;;
  *) sed -n '2,9p' "$0" >&2; exit 2 ;;
esac
`
	ceph := `#!/bin/sh
# ceph-ro: Ceph commands its own command table marks read-only (ADR 0019).
#   ceph-ro osd df -f json     ceph-ro pg 25.d7 query
S=` + dir + `/ceph.sock
H="` + CallHeader + `: ${ADVISOR_CALL_ID:-}"
python3 -c 'import json,sys; print(json.dumps({"args": sys.argv[1:]}))' "$@" |
  curl -sS --unix-socket "$S" -H "$H" -H 'Content-Type: application/json' --data-binary @- http://broker/run
`
	host := `#!/bin/sh
# host-ro: the host's state the sandbox cannot see (ADR 0019).
#   host-ro sockets [PORT]  listening TCP/UDP sockets on the host, optionally one local port
#   host-ro unit NAME       a systemd unit's state, e.g. host-ro unit sshd
S=` + dir + `/host.sock
H="` + CallHeader + `: ${ADVISOR_CALL_ID:-}"
case "$1" in
  sockets) curl -sS --unix-socket "$S" -H "$H" -G http://broker/sockets ${2:+--data-urlencode "port=$2"} ;;
  unit) curl -sS --unix-socket "$S" -H "$H" -G http://broker/unit --data-urlencode "name=$2" ;;
  *) sed -n '2,4p' "$0" >&2; exit 2 ;;
esac
`
	return map[string]string{"prom": prom, "ceph-ro": ceph, "host-ro": host}
}
