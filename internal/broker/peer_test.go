package broker

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/facts"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

type scriptCall struct {
	node, script string
	args         []string
}

type peerRuns struct {
	mu  sync.Mutex
	ran []scriptCall
}

func (p *peerRuns) all() []scriptCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]scriptCall(nil), p.ran...)
}

// startPeers serves a broker on node cube-a of cube-a, cube-b and cube-c;
// cube-c does not answer.
func startPeers(t *testing.T) (*memAudit, string, *peerRuns) {
	t.Helper()
	p := &peerRuns{}
	_, audit, dir := start(t, http.NotFoundHandler(), func(s *Server) {
		s.Nodes = func(context.Context) ([]string, error) { return []string{"cube-a", "cube-b", "cube-c"}, nil }
		s.Hostname = func() (string, error) { return "cube-a.local", nil }
		s.HostRun = func(context.Context, string, []string) ([]byte, []byte, error) {
			t.Error("a peer read ran locally")
			return nil, nil, nil
		}
		s.ScriptRun = func(_ context.Context, node, script string, args []string) ([]byte, []byte, error) {
			p.mu.Lock()
			p.ran = append(p.ran, scriptCall{node, script, args})
			p.mu.Unlock()
			if node == "cube-c" {
				return nil, []byte("ssh: connect to host cube-c port 22: No route to host\n"), errUnreachable
			}
			return []byte("read on " + node + "  \n"), nil, nil
		}
	})
	return audit, dir, p
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Each view runs its fixed script on the named node, with only its
// validated argument, and is audited with the node.
func TestHostRunsTheSameViewOnAPeer(t *testing.T) {
	audit, dir, ran := startPeers(t)
	c := unixClient(filepath.Join(dir, "host.sock"))
	for _, u := range []string{"failed", "procs", "errlog", "oom", "logsize", "unowned", "facts", "sockets?port=22", "unit?name=sshd"} {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		code, body := get(t, c, "http://broker/"+u+sep+"node=cube-b")
		if code != 200 || body != "read on cube-b\n" {
			t.Fatalf("%s: %d %q", u, code, body)
		}
	}
	got := ran.all()
	views := []string{"failed", "procs", "errlog", "oom", "logsize", "unowned", "facts", "sockets", "unit"}
	if len(got) != len(views) {
		t.Fatalf("ran %d scripts, want %d", len(got), len(views))
	}
	for i, v := range views {
		if got[i].node != "cube-b" || got[i].script != viewScripts[v] {
			t.Errorf("%s ran %+v", v, got[i])
		}
	}
	if strings.Join(got[7].args, " ") != "22" || strings.Join(got[8].args, " ") != "sshd" || len(got[0].args) != 0 || len(got[6].args) != 0 {
		t.Errorf("arguments: %v %v %v %v", got[0].args, got[6].args, got[7].args, got[8].args)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, a := range audit.calls {
		if !a.Allowed || a.Tool != "broker:host" || a.Args["node"] != "cube-b" {
			t.Errorf("audit = %+v", a)
		}
	}
}

func TestHostRefusesNodesOutsideTheCluster(t *testing.T) {
	audit, dir, ran := startPeers(t)
	c := unixClient(filepath.Join(dir, "host.sock"))
	for _, u := range []string{
		"failed?node=cube-z", "failed?node=-oProxyCommand=reboot", "failed?node=cube-b%20reboot", "failed?node=root@cube-b",
		"nodes?node=cube-b", "unit?name=a;reboot&node=cube-b", "sockets?port=22;reboot&node=cube-b", "run?node=cube-b",
	} {
		if code, _ := get(t, c, "http://broker/"+u); code < 400 {
			t.Errorf("%s: %d, want refused", u, code)
		}
	}
	if got := ran.all(); len(got) != 0 {
		t.Fatalf("refused reads ran %v", got)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.calls) != 8 {
		t.Fatalf("audited %d, want 8", len(audit.calls))
	}
	for _, a := range audit.calls {
		if a.Allowed {
			t.Errorf("refusal recorded as allowed: %+v", a)
		}
	}
}

func TestHostSaysWhenAPeerIsUnreachable(t *testing.T) {
	audit, dir, _ := startPeers(t)
	code, body := get(t, unixClient(filepath.Join(dir, "host.sock")), "http://broker/failed?node=cube-c")
	if code != http.StatusBadGateway || !strings.HasPrefix(body, tunnelproto.PeerUnreachable+": cube-c: ssh: connect") {
		t.Fatalf("%d %q", code, body)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if a := audit.calls[0]; !a.Allowed || !strings.HasPrefix(a.Reason, tunnelproto.PeerUnreachable) {
		t.Errorf("audit = %+v", a)
	}
}

func TestHostListsTheClusterNodes(t *testing.T) {
	_, dir, _ := startPeers(t)
	code, body := get(t, unixClient(filepath.Join(dir, "host.sock")), "http://broker/nodes")
	if code != 200 || body != "cube-a\tself\ncube-b\ncube-c\n" {
		t.Fatalf("%d %q", code, body)
	}
}

func TestParseNodeList(t *testing.T) {
	// cubectl node list -j on r730lab00019 (3.2.0), plus two peers.
	raw := `[{"hostname":"cube-r730","role":"control-converged","ip":{"management":"10.32.1.210"}},` +
		`{"hostname":"compute-1","role":"compute"},{"hostname":"-oProxyCommand=x","role":"compute"}]`
	got, err := ParseNodeList([]byte(raw))
	if err != nil || strings.Join(got, ",") != "cube-r730,compute-1" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestHostClientPassesTheNode(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	_, dir, ran := startPeers(t)
	hostro := filepath.Join(dir, "bin", "host-ro")
	out, err := exec.Command(hostro, "--node", "cube-b", "sockets", "22").CombinedOutput()
	if err != nil || string(out) != "read on cube-b\n" {
		t.Fatalf("host-ro --node cube-b sockets 22: %q %v", out, err)
	}
	out, _ = exec.Command(hostro, "--node", "cube-c", "oom").CombinedOutput()
	if !strings.HasPrefix(string(out), tunnelproto.PeerUnreachable) {
		t.Fatalf("host-ro --node cube-c oom: %q", out)
	}
	out, err = exec.Command(hostro, "--node", "cube-b", "facts").CombinedOutput()
	if err != nil || string(out) != "read on cube-b\n" {
		t.Fatalf("host-ro --node cube-b facts: %q %v", out, err)
	}
	if got := ran.all(); len(got) != 3 || got[0].args[0] != "22" || got[1].script != viewScripts["oom"] || got[2].script != facts.Script {
		t.Fatalf("ran %+v", got)
	}
}

// The facts view runs the one facts script the Advisor also runs in the
// sandbox, so a relayed node reports what a node with an agent does.
func TestFactsViewIsTheSharedScript(t *testing.T) {
	if viewScripts["facts"] != facts.Script || !strings.Contains(facts.Script, "##hostname") {
		t.Fatal("the facts view is not facts.Script")
	}
}

// fakeSSH puts an ssh on PATH that logs its argv and runs the remote
// command with sh locally, as sshd would; FAKE_SSH_DOWN makes it fail to
// connect.
func fakeSSH(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "argv")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + log + "\n" +
		"[ -n \"$FAKE_SSH_DOWN\" ] && { echo 'ssh: connect to host x port 22: Connection timed out' >&2; exit 255; }\n" +
		"while [ $# -gt 0 ]; do case \"$1\" in root@*) shift; break;; esac; shift; done\n" +
		"exec sh -c \"$*\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return log
}

func TestRunScriptOverSSH(t *testing.T) {
	log := fakeSSH(t)
	out, _, err := RunScript(context.Background(), "cube-b", `echo "view $1"`, []string{"22"})
	if err != nil || string(out) != "view 22\n" {
		t.Fatalf("%q %v", out, err)
	}
	argv, _ := os.ReadFile(log)
	want := strings.Join(SSHCommand("cube-b", []string{"22"})[1:], "\n") + "\n"
	if string(argv) != want {
		t.Fatalf("ssh argv\n%s\nwant\n%s", argv, want)
	}
	for _, o := range []string{"BatchMode=yes", "ConnectTimeout=10", "root@cube-b"} {
		if !strings.Contains(string(argv), o) {
			t.Errorf("ssh argv lacks %s", o)
		}
	}
	t.Setenv("FAKE_SSH_DOWN", "1")
	if _, errOut, err := RunScript(context.Background(), "cube-b", "true", nil); err != errUnreachable || !strings.Contains(string(errOut), "timed out") {
		t.Fatalf("unreachable: %v %q", err, errOut)
	}
}

func TestRunScriptCapsTheAnswer(t *testing.T) {
	out, _, err := RunScript(context.Background(), "", "head -c "+strconv.Itoa(MaxResponse+100)+" /dev/zero", nil)
	if err != nil || len(out) > MaxResponse+100 || !strings.Contains(string(out[MaxResponse:]), "answer cut") {
		t.Fatalf("len %d %v", len(out), err)
	}
}

// The peer process listing matches listProcs line for line.
func TestPeerProcsMatchListProcs(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	root := interpreterFixture(t)
	py, err := exec.Command("python3", "-c", procsPy, root).Output()
	if err != nil {
		t.Fatal(err)
	}
	if goOut := string(listProcs(root)); string(py) != goOut {
		t.Fatalf("python\n%s\ngo\n%s", py, goOut)
	}

	// And on this host's /proc, for a running interpreter script.
	f := filepath.Join(t.TempDir(), "s.sh")
	_ = os.WriteFile(f, []byte("sleep 30\n"), 0o644)
	cmd := exec.Command("sh", f, "--token", "s3cret")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	time.Sleep(100 * time.Millisecond)
	pid := strconv.Itoa(cmd.Process.Pid)
	line := func(out []byte) string {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, pid+"\t") {
				return l
			}
		}
		return ""
	}
	py, _ = exec.Command("python3", "-c", procsPy).Output()
	if g, p := line(listProcs("")), line(py); g == "" || g != p || !strings.HasSuffix(g, "\t"+f) || strings.Contains(p, "s3cret") {
		t.Fatalf("go %q\npython %q", g, p)
	}
}

// The view scripts run with sh and print what the scan parses.
func TestViewScriptsRunHere(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	for view, want := range map[string]string{"logsize": "##logdir", "unowned": "##installed", "procs": "\t", "facts": "##hostname", "errlog": "", "oom": ""} {
		out, errOut, err := RunScript(context.Background(), "", viewScripts[view], nil)
		if err != nil || !strings.Contains(string(out), want) {
			t.Errorf("%s: %v %q %q", view, err, out, errOut)
		}
	}
}
