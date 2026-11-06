package broker

import (
	"context"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// hostRuns records the commands the host broker ran.
type hostRuns struct {
	mu  sync.Mutex
	ran [][]string
}

func (h *hostRuns) all() [][]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]string(nil), h.ran...)
}

func startHost(t *testing.T) (*memAudit, string, *hostRuns) {
	t.Helper()
	h := &hostRuns{}
	_, audit, dir := start(t, http.NotFoundHandler(), func(s *Server) {
		s.HostRun = func(_ context.Context, name string, args []string) ([]byte, []byte, error) {
			h.mu.Lock()
			h.ran = append(h.ran, append([]string{name}, args...))
			h.mu.Unlock()
			if name == "ss" {
				return []byte("tcp LISTEN 0 128 10.32.1.210:22 0.0.0.0:* users:((\"sshd\",pid=5234,fd=3))      \n"), nil, nil
			}
			return []byte("Id=sshd.service\nActiveState=active\nSubState=running\n"), nil, nil
		}
	})
	return audit, dir, h
}

func TestHostServesSocketsAndUnitState(t *testing.T) {
	_, dir, ran := startHost(t)
	c := unixClient(filepath.Join(dir, "host.sock"))
	get := func(url string) (int, string) {
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("http://broker/sockets"); code != 200 || !strings.Contains(body, "10.32.1.210:22") {
		t.Fatalf("sockets: %d %q", code, body)
	}
	if code, body := get("http://broker/sockets?port=22"); code != 200 || strings.Contains(body, " \n") {
		t.Fatalf("sockets port=22 kept the padding: %d %q", code, body)
	}
	if code, body := get("http://broker/unit?name=sshd"); code != 200 || !strings.Contains(body, "ActiveState=active") {
		t.Fatalf("unit: %d %q", code, body)
	}
	want := [][]string{{"ss", "-H", "-l", "-t", "-u", "-n", "-p"},
		{"ss", "-H", "-l", "-t", "-u", "-n", "-p", "sport", "=", ":22"},
		{"systemctl", "show", "--no-pager", "-p", unitProps, "--", "sshd"}}
	got := ran.all()
	if len(got) != 3 {
		t.Fatalf("ran %v", got)
	}
	for i := range want {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			t.Fatalf("call %d ran %v, want %v", i, got[i], want[i])
		}
	}
}

func TestHostRefusesAnythingElse(t *testing.T) {
	audit, dir, ran := startHost(t)
	c := unixClient(filepath.Join(dir, "host.sock"))
	for _, tc := range []struct{ method, url string }{
		{http.MethodGet, "http://broker/unit?name=--user"},
		{http.MethodGet, "http://broker/unit?name=sshd%20restart"},
		{http.MethodGet, "http://broker/unit?name=a;reboot"},
		{http.MethodGet, "http://broker/unit"},
		{http.MethodGet, "http://broker/run?cmd=reboot"},
		{http.MethodGet, "http://broker/sockets?port=22;reboot"},
		{http.MethodGet, "http://broker/sockets?port=0"},
		{http.MethodGet, "http://broker/sockets?port=022"},
		{http.MethodPost, "http://broker/sockets"},
	} {
		req, _ := http.NewRequest(tc.method, tc.url, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Errorf("%s %s: %d, want refused", tc.method, tc.url, resp.StatusCode)
		}
	}
	if got := ran.all(); len(got) != 0 {
		t.Fatalf("refused calls ran %v", got)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.calls) != 9 {
		t.Fatalf("audited %d calls, want 9", len(audit.calls))
	}
	for _, c := range audit.calls {
		if c.Allowed || c.Tool != "broker:host" {
			t.Errorf("refusal recorded wrong: %+v", c)
		}
	}
}

func TestHostClientReachesTheBroker(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	_, dir, _ := startHost(t)
	out, err := exec.Command(filepath.Join(dir, "bin", "host-ro"), "sockets").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "sshd") {
		t.Fatalf("host-ro sockets: %q %v", out, err)
	}
	out, err = exec.Command(filepath.Join(dir, "bin", "host-ro"), "sockets", "22").CombinedOutput()
	if err != nil || !strings.Contains(string(out), ":22") {
		t.Fatalf("host-ro sockets 22: %q %v", out, err)
	}
	out, err = exec.Command(filepath.Join(dir, "bin", "host-ro"), "unit", "sshd").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "SubState=running") {
		t.Fatalf("host-ro unit: %q %v", out, err)
	}
}
