package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// KubeConfig is the node's k3s admin kubeconfig.
var KubeConfig = "/etc/rancher/k3s/k3s.yaml"

// kubeBinaries are where k3s lives on CubeCOS; it serves `k3s kubectl`.
var kubeBinaries = []string{"/usr/local/bin/k3s", "/sbin/k3s", "/usr/bin/k3s"}

// Limits on one kube-ro call.
const (
	kubeMaxArgs        = 64
	kubeRequestTimeout = "50s"
)

// kubeVerbs are the kubectl commands kube-ro runs: each only issues GETs.
var kubeVerbs = map[string]bool{"get": true, "describe": true, "logs": true, "events": true, "top": true,
	"api-resources": true, "api-versions": true, "version": true}

// kubeFlags are the accepted options; true when the option takes a value.
var kubeFlags = map[string]bool{
	"-n": true, "--namespace": true, "-A": false, "--all-namespaces": false,
	"-l": true, "--selector": true, "--field-selector": true,
	"-o": true, "--output": true, "--sort-by": true, "-L": true, "--label-columns": true,
	"--show-labels": false, "--no-headers": false, "--show-kind": false, "--ignore-not-found": false,
	"--chunk-size": true, "--show-managed-fields": false, "--raw": true, "--show-events": false,
	"--tail": true, "--since": true, "--since-time": true, "-c": true, "--container": true,
	"--all-containers": false, "-p": false, "--previous": false, "--timestamps": false, "--prefix": false,
	"--limit-bytes": true, "--max-log-requests": true, "--ignore-errors": false,
	"--for": true, "--types": true, "--containers": false, "--sum": false, "--use-protocol-buffers": false,
	"--api-group": true, "--namespaced": false, "--verbs": true, "--client": false,
}

// kubeNeverReturns are options that follow or watch until stopped.
var kubeNeverReturns = map[string]bool{"-w": true, "--watch": true, "--watch-only": true, "--follow": true}

// kubeOutputs are -o formats; *-file formats read host files and are refused.
var kubeOutputs = regexp.MustCompile(`^(json|yaml|wide|name|(custom-columns|jsonpath|jsonpath-as-json|go-template)=.*)$`)

var kubeWord = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/,=@-]*$`)

// kubeRawRoots are the API paths `get --raw` reads.
var kubeRawRoots = []string{"/api", "/apis", "/version", "/healthz", "/livez", "/readyz", "/metrics", "/openapi"}

// kubeNodeProxy is the one proxy kube-ro reaches: the kubelet's own read
// endpoints (its effective config, health, metrics, stats).
var kubeNodeProxy = regexp.MustCompile(`^/api/v1/nodes/[a-z0-9.-]+/proxy/(configz|healthz|metrics|metrics/cadvisor|metrics/resource|metrics/probes|stats/summary|pods|spec)$`)

// kubeDeniedSegments are path segments that expose secrets or are not reads:
// secret values, a container's shell or ports, an app's own endpoints.
var kubeDeniedSegments = map[string]bool{"secrets": true, "exec": true, "attach": true, "portforward": true,
	"proxy": true, "token": true}

// CheckKubeArgs decides whether args (the words after "kubectl") may run.
func CheckKubeArgs(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kube-ro get|describe|logs|events|top|api-resources|api-versions|version ...")
	}
	if len(args) > kubeMaxArgs {
		return fmt.Errorf("at most %d arguments", kubeMaxArgs)
	}
	var verb, raw string
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			if verb == "" {
				if verb = a; !kubeVerbs[verb] {
					return fmt.Errorf("%q is not a kube-ro command; it runs get, describe, logs, events, top, api-resources, api-versions and version", verb)
				}
				continue
			}
			if !kubeWord.MatchString(a) {
				return fmt.Errorf("argument %q: only names, TYPE/NAME and comma lists are accepted", a)
			}
			pos = append(pos, a)
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		// Short options may carry their value: -ojson, -nkube-system.
		if !hasVal && len(a) > 2 && a[1] != '-' {
			name, val, hasVal = a[:2], a[2:], true
		}
		if name == "-f" {
			return errors.New("-f follows logs or names a file, and is refused; read once (logs --tail N)")
		}
		if kubeNeverReturns[name] {
			return fmt.Errorf("%s follows or watches until stopped; read once", name)
		}
		takes, ok := kubeFlags[name]
		if !ok {
			return fmt.Errorf("option %s is not accepted by kube-ro", name)
		}
		if takes && !hasVal {
			if i+1 >= len(args) {
				return fmt.Errorf("%s takes a value", name)
			}
			i++
			val = args[i]
		}
		if !takes && hasVal && val != "true" && val != "false" {
			return fmt.Errorf("%s takes no value", name)
		}
		switch name {
		case "-o", "--output":
			if !kubeOutputs.MatchString(val) {
				return fmt.Errorf("-o %s: use json, yaml, wide, name, custom-columns=, jsonpath= or go-template= (no *-file formats)", val)
			}
		case "--raw":
			raw = val
		}
	}
	if verb == "" {
		return errors.New("no command: kube-ro get|describe|logs|events|top|api-resources|api-versions|version ...")
	}
	if raw != "" {
		if verb != "get" || len(pos) > 0 {
			return errors.New("--raw goes with get alone: kube-ro get --raw /api/v1/...")
		}
		return CheckKubeRawPath(raw)
	}
	if verb == "get" || verb == "describe" {
		for i, p := range pos {
			types := []string{}
			if t, _, ok := strings.Cut(p, "/"); ok {
				types = append(types, t)
			} else if i == 0 {
				types = strings.Split(p, ",")
			}
			for _, t := range types {
				if t, _, _ = strings.Cut(strings.ToLower(t), "."); t == "secret" || t == "secrets" {
					return errors.New("secrets are not served: their values are credentials")
				}
			}
		}
	}
	return nil
}

// CheckKubeRawPath allows a GET of an API, health or metrics path; never
// secrets, exec/attach/port-forward, a proxy other than the kubelet's own
// read endpoints, or a watch.
func CheckKubeRawPath(raw string) error {
	p, q, _ := strings.Cut(raw, "?")
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.Contains(p, "//") || strings.ContainsAny(raw, "%\\ \t\n") {
		return fmt.Errorf("--raw %s: give a plain absolute API path", raw)
	}
	root := false
	for _, r := range kubeRawRoots {
		if p == r || strings.HasPrefix(p, r+"/") {
			root = true
		}
	}
	if !root {
		return fmt.Errorf("--raw %s: only paths under %s are read", raw, strings.Join(kubeRawRoots, ", "))
	}
	for _, kv := range strings.Split(q, "&") {
		if k, _, _ := strings.Cut(kv, "="); strings.EqualFold(k, "watch") || strings.EqualFold(k, "follow") {
			return fmt.Errorf("--raw %s: %s never returns; read once", raw, k)
		}
	}
	if kubeNodeProxy.MatchString(p) {
		return nil
	}
	for _, seg := range strings.Split(strings.ToLower(p), "/") {
		if kubeDeniedSegments[seg] {
			return fmt.Errorf("--raw %s: %q paths are not served (secrets, a container's shell or an app's own endpoints); "+
				"the kubelet's own reads are /api/v1/nodes/<node>/proxy/configz|healthz|metrics|stats/summary", raw, seg)
		}
	}
	return nil
}

// KubeAvailable says this node runs k3s with its admin kubeconfig.
func KubeAvailable() bool {
	if _, err := os.Stat(KubeConfig); err != nil {
		return false
	}
	return kubeBinary() != ""
}

func kubeBinary() string {
	for _, b := range kubeBinaries {
		if fi, err := os.Stat(b); err == nil && !fi.IsDir() {
			return b
		}
	}
	if p, err := exec.LookPath("k3s"); err == nil {
		return p
	}
	return ""
}

// LocalKubeRun runs `k3s kubectl args...` against the node's k3s, without a
// shell; its discovery cache stays out of root's home.
func LocalKubeRun(ctx context.Context, args []string) ([]byte, []byte, error) {
	bin := kubeBinary()
	if bin == "" {
		return nil, nil, errors.New("k3s not found")
	}
	full := append([]string{"kubectl", "--kubeconfig", KubeConfig, "--request-timeout", kubeRequestTimeout,
		"--cache-dir", filepath.Join(os.TempDir(), "cube-advisor-agent-kube-cache")}, args...)
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, full...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// kube serves kube-ro: POST {"args":[...]} to /run.
func (s *Server) kube(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var in struct {
		Args []string `json:"args"`
	}
	args := map[string]string{}
	refuse := func(code int, why string) {
		s.record(r, "broker:kube", args, false, why, started, 0)
		http.Error(w, why, code)
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&in) != nil {
		refuse(http.StatusBadRequest, `POST {"args":[...]}`)
		return
	}
	args["args"] = strings.Join(in.Args, " ")
	if s.KubeRun == nil {
		refuse(http.StatusServiceUnavailable, "this node runs no k3s (no "+KubeConfig+"), so kube-ro has nothing to read")
		return
	}
	if err := CheckKubeArgs(in.Args); err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), CallTimeout)
	defer cancel()
	out, errOut, err := s.KubeRun(ctx, in.Args)
	if len(out) > MaxResponse {
		out = append(out[:MaxResponse], fmt.Sprintf("\n[broker: answer cut at %d bytes]\n", MaxResponse)...)
	}
	reason := ""
	code := http.StatusOK
	if err != nil {
		reason, code = err.Error(), http.StatusBadGateway
		out = append(out, errOut...)
	}
	s.record(r, "broker:kube", args, true, reason, started, len(out))
	w.WriteHeader(code)
	_, _ = w.Write(out)
}
