package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// A slice of the monitor's real command table (3.2.0 rc4).
const descriptions = `{
 "c1": {"sig": ["osd", "df", {"name": "output_method", "type": "CephChoices", "req": "false"}], "perm": "r"},
 "c2": {"sig": ["osd", "out", {"name": "ids", "type": "CephString", "n": "N"}], "perm": "rw"},
 "c3": {"sig": ["osd", "purge", {"name": "id", "type": "CephOsdName"}, {"name": "yes_i_really_mean_it", "type": "CephBool", "req": "false"}], "perm": "rw"},
 "c4": {"sig": ["status"], "perm": "r"},
 "c5": {"sig": ["health", {"name": "detail", "type": "CephChoices", "req": "false"}], "perm": "r"},
 "c6": {"sig": ["health", "mute", {"name": "code", "type": "CephString"}], "perm": "w"},
 "c7": {"sig": ["osd", "pool", "get", {"name": "pool", "type": "CephPoolname"}, {"name": "var", "type": "CephChoices"}], "perm": "r"},
 "c8": {"sig": ["osd", "pool", "set", {"name": "pool", "type": "CephPoolname"}, {"name": "var", "type": "CephChoices"}, {"name": "val", "type": "CephString"}], "perm": "rw"},
 "c9": {"sig": ["df", {"name": "detail", "type": "CephChoices", "req": "false"}], "perm": "r"},
 "c10": {"sig": ["config", "set", {"name": "who", "type": "CephString"}, {"name": "name", "type": "CephString"}, {"name": "value", "type": "CephString"}], "perm": "rw"},
 "c11": {"sig": ["tell", {"name": "target", "type": "CephName"}, {"name": "args", "type": "CephString", "n": "N"}], "perm": "rw"}
}`

func table(t *testing.T) []CephCommand {
	t.Helper()
	tb, err := ParseCephDescriptions([]byte(descriptions))
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestOnlyCommandsCephMarksReadOnlyPass(t *testing.T) {
	tb := table(t)
	for _, ok := range [][]string{
		{"status"}, {"osd", "df", "-f", "json"}, {"health", "detail"}, {"df", "--format=json-pretty"},
		{"osd", "pool", "get", "rbd", "size"}, {"pg", "25.d7", "query"}, {"pg", "25.d7", "list_unfound"},
	} {
		if err := CheckCephArgs(tb, ok); err != nil {
			t.Errorf("%v refused: %v", ok, err)
		}
	}
	for _, bad := range [][]string{
		{"osd", "out", "4"}, {"osd", "purge", "4", "--yes-i-really-mean-it"}, {"health", "mute", "OSD_DOWN"},
		{"osd", "pool", "set", "rbd", "size", "1"}, {"config", "set", "osd", "x", "1"}, {"tell", "osd.4", "bench"},
		{"pg", "25.d7", "mark_unfound_lost", "delete"}, {"status", "--admin-socket", "/x"}, {"osd", "df", "-f", "yaml"},
		{"no", "such", "command"}, {},
	} {
		if err := CheckCephArgs(tb, bad); err == nil {
			t.Errorf("%v allowed", bad)
		}
	}
}

type memAudit struct {
	mu    sync.Mutex
	calls []toolplane.ToolCall
}

func (a *memAudit) RecordToolCall(c toolplane.ToolCall) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, c)
}

func start(t *testing.T, prom http.Handler) (*Server, *memAudit, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "brk") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	backend := httptest.NewServer(prom)
	t.Cleanup(backend.Close)
	audit := &memAudit{}
	var ran [][]string
	s := &Server{Dir: dir, Prometheus: backend.URL + "/prometheus", Audit: audit,
		CephTable: func(context.Context) ([]CephCommand, error) { return table(t), nil },
		CephRun: func(_ context.Context, args []string) ([]byte, []byte, error) {
			ran = append(ran, args)
			return []byte(`{"ran":"` + strings.Join(args, " ") + `"}`), nil, nil
		}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return s, audit, dir
}

func unixClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}

func TestPromForwardsQueriesAndRefusesWritesAndConfig(t *testing.T) {
	var seen []string
	_, audit, dir := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		_, _ = io.WriteString(w, `{"status":"success"}`)
	}))
	c := unixClient(filepath.Join(dir, "prom.sock"))
	get := func(path string) int {
		req, _ := http.NewRequest(http.MethodGet, "http://broker"+path, nil)
		req.Header.Set(CallHeader, "run-1")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("/api/v1/query?query=up"); code != 200 {
		t.Fatalf("query: %d", code)
	}
	if len(seen) != 1 || seen[0] != "GET /prometheus/api/v1/query?query=up" {
		t.Fatalf("backend saw %v", seen)
	}
	for _, p := range []string{"/api/v1/admin/tsdb/delete_series?match[]=up", "/api/v1/write", "/api/v1/status/config", "/-/quit", "/api/v1/../-/reload", "/metrics"} {
		if code := get(p); code == 200 {
			t.Errorf("%s forwarded", p)
		}
	}
	resp, _ := c.Post("http://broker/api/v1/query", "application/x-www-form-urlencoded", strings.NewReader("query=up"))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	if len(seen) != 1 {
		t.Fatalf("refused calls reached Prometheus: %v", seen)
	}
	if a := audit.calls[0]; a.Tool != "broker:prom" || !a.Allowed || a.Args["call"] != "run-1" {
		t.Errorf("audit = %+v", a)
	}
}

func TestCephRunsOnlyReadOnlyCommands(t *testing.T) {
	_, audit, dir := start(t, http.NotFoundHandler())
	c := unixClient(filepath.Join(dir, "ceph.sock"))
	run := func(args ...string) (int, string) {
		b, _ := json.Marshal(map[string]any{"args": args})
		resp, err := c.Post("http://broker/run", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}
	if code, out := run("osd", "df", "-f", "json"); code != 200 || !strings.Contains(out, `"ran":"osd df -f json"`) {
		t.Fatalf("osd df: %d %s", code, out)
	}
	if code, out := run("osd", "out", "4"); code != http.StatusForbidden || !strings.Contains(out, `marked "rw"`) {
		t.Fatalf("osd out: %d %s", code, out)
	}
	if n := len(audit.calls); n != 2 || audit.calls[1].Allowed {
		t.Fatalf("audit = %+v", audit.calls)
	}
}

// The client commands as the sandbox runs them, against a live broker.
func TestClientCommandsReachTheBrokers(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	_, _, dir := start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "q="+r.URL.Query().Get("query"))
	}))
	out, err := exec.Command(filepath.Join(dir, "bin", "prom"), "query", `sum(up{job="ceph"})`).CombinedOutput()
	if err != nil || string(out) != `q=sum(up{job="ceph"})` {
		t.Fatalf("prom query: %q %v", out, err)
	}
	out, err = exec.Command(filepath.Join(dir, "bin", "ceph-ro"), "pg", "25.d7", "query").CombinedOutput()
	if err != nil || !strings.Contains(string(out), `"ran":"pg 25.d7 query"`) {
		t.Fatalf("ceph-ro: %q %v", out, err)
	}
	out, _ = exec.Command(filepath.Join(dir, "bin", "ceph-ro"), "osd", "out", "4").CombinedOutput()
	if !strings.Contains(string(out), "not read-only") {
		t.Fatalf("ceph-ro osd out: %q", out)
	}
}
