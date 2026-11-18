package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestKubeArgsAllowOnlyReads(t *testing.T) {
	for _, ok := range []string{
		"get pods -A -o wide", "get nodes -ojson", "get pods -nkube-system", "describe node cube-r730",
		"get pod/rancher-1 -n cattle-system -o yaml", "get deploy,svc,ingress -A",
		"logs -n ingress-nginx ingress-nginx-controller-abc --tail 200 --previous", "logs deploy/rancher -n cattle-system --since=2h",
		"events -A --for pod/x", "get events -A --sort-by=.lastTimestamp", "top node", "top pod -A --containers",
		"api-resources --verbs=list --namespaced", "api-versions", "version", "get --raw /api/v1/nodes/cube-r730/proxy/configz",
		"get --raw /api/v1/nodes/cube-r730/proxy/stats/summary", "get --raw /apis/apps/v1/deployments?limit=5",
		"get --raw=/healthz", "get --raw /metrics", "get pods -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName",
		"get pods -o jsonpath={.items[*].status.phase}", "get configmaps -n kube-system", "get pods --show-labels=true",
	} {
		if err := CheckKubeArgs(strings.Fields(ok)); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for bad, why := range map[string]string{
		"get secrets -A":                                           "secrets",
		"get secret x -o yaml":                                     "secrets",
		"get Secrets.v1 -A -o json":                                "secrets",
		"get pods,secrets -A":                                      "secrets",
		"get pod/x secret/y -o json":                               "secrets",
		"describe secret x":                                        "secrets",
		"get --raw /api/v1/namespaces/a/secrets":                   "secrets",
		"get --raw /api/v1/secrets?limit=1":                        "secrets",
		"get --raw /api/v1/namespaces/a/pods/p/exec?command=sh":    "exec",
		"get --raw /api/v1/namespaces/a/pods/p/portforward":        "portforward",
		"get --raw /api/v1/namespaces/a/services/s:80/proxy/admin": "proxy",
		"get --raw /api/v1/nodes/n/proxy/logs/messages":            "proxy",
		"get --raw /api/v1/nodes/n/proxy/run/ns/p/c":               "proxy",
		"get --raw /api/v1/pods?watch=true":                        "never returns",
		"get --raw /api/v1/../../etc":                              "plain absolute",
		"get --raw /logs/":                                         "only paths under",
		"get pods --raw /api":                                      "alone",
		"describe --raw /api":                                      "alone",
		"delete pod x":                                             "not a kube-ro command",
		"exec -it p -- sh":                                         "not a kube-ro command",
		"port-forward p 80":                                        "not a kube-ro command",
		"proxy":                                                    "not a kube-ro command",
		"cp p:/etc/x /tmp":                                         "not a kube-ro command",
		"apply -f x.yaml":                                          "not a kube-ro command",
		"edit deploy x":                                            "not a kube-ro command",
		"cordon n":                                                 "not a kube-ro command",
		"get pods -w":                                              "follows or watches",
		"logs -f p":                                                "follows logs",
		"events --watch":                                           "follows or watches",
		"get pods --kubeconfig /root/x":                            "not accepted",
		"get pods -s https://evil:6443":                            "not accepted",
		"get pods --as=system:admin":                               "not accepted",
		"get pods --token x":                                       "not accepted",
		"get pods -v=9":                                            "not accepted",
		"get pods --cache-dir /etc":                                "not accepted",
		"get -f /etc/shadow":                                       "names a file",
		"-n x":                                                     "no command",
		"get pods -o go-template-file=/etc/shadow":                 "no *-file",
		"get pods -o jsonpath-file=/etc/shadow":                    "no *-file",
		"get pods --all-namespaces=yes":                            "takes no value",
		"get pods $(id)":                                           "only names",
		"":                                                         "usage",
	} {
		err := CheckKubeArgs(strings.Fields(bad))
		if err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want refused (%s)", bad, err, why)
		}
	}
}

func TestKubeBrokerRunsOnlyCheckedCalls(t *testing.T) {
	var ran [][]string
	_, audit, dir := start(t, http.NotFoundHandler(), func(s *Server) {
		s.KubeRun = func(_ context.Context, args []string) ([]byte, []byte, error) {
			ran = append(ran, args)
			return []byte("ran " + strings.Join(args, " ")), nil, nil
		}
	})
	c := unixClient(filepath.Join(dir, "kube.sock"))
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
	if code, out := run("get", "--raw", "/api/v1/nodes/cube-r730/proxy/configz"); code != 200 || out != "ran get --raw /api/v1/nodes/cube-r730/proxy/configz" {
		t.Fatalf("configz: %d %s", code, out)
	}
	if code, out := run("get", "secrets", "-A"); code != http.StatusForbidden || !strings.Contains(out, "secrets are not served") {
		t.Fatalf("secrets: %d %s", code, out)
	}
	if len(ran) != 1 {
		t.Fatalf("refused call reached kubectl: %v", ran)
	}
	if n := len(audit.calls); n != 2 || audit.calls[0].Tool != "broker:kube" || !audit.calls[0].Allowed || audit.calls[1].Allowed {
		t.Fatalf("audit = %+v", audit.calls)
	}
}

// A node without k3s refuses, and says why.
func TestKubeBrokerWithoutK3sRefuses(t *testing.T) {
	_, _, dir := start(t, http.NotFoundHandler())
	c := unixClient(filepath.Join(dir, "kube.sock"))
	resp, err := c.Post("http://broker/run", "application/json", strings.NewReader(`{"args":["get","pods"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(out), "no k3s") {
		t.Fatalf("%d %s", resp.StatusCode, out)
	}
}

func TestKubeROClientReachesTheBroker(t *testing.T) {
	for _, c := range []string{"curl", "python3"} {
		if _, err := exec.LookPath(c); err != nil {
			t.Skip("no " + c)
		}
	}
	_, _, dir := start(t, http.NotFoundHandler(), func(s *Server) {
		s.KubeRun = func(_ context.Context, args []string) ([]byte, []byte, error) {
			return []byte("ran " + strings.Join(args, "|")), nil, nil
		}
	})
	out, err := exec.Command(filepath.Join(dir, "bin", "kube-ro"), "get", "pods", "-o", "jsonpath={.items[*].metadata.name}").CombinedOutput()
	if err != nil || string(out) != "ran get|pods|-o|jsonpath={.items[*].metadata.name}" {
		t.Fatalf("kube-ro: %q %v", out, err)
	}
	out, _ = exec.Command(filepath.Join(dir, "bin", "kube-ro"), "delete", "pod", "x").CombinedOutput()
	if !strings.Contains(string(out), "not a kube-ro command") {
		t.Fatalf("kube-ro delete: %q", out)
	}
}
