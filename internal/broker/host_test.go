package broker

import (
	"context"
	"io"
	"net/http"
	"os"
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

// /procs lists each process's executable from outside the sandbox, which may
// not resolve /proc/PID/exe; never its command line (#371).
func TestHostListsProcessExecutables(t *testing.T) {
	root := t.TempDir()
	mk := func(pid, comm, uid, exe string) {
		d := filepath.Join(root, pid)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "status"), []byte("Name:\t"+comm+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "cmdline"), []byte("secret-arg"), 0o644)
		if exe != "" {
			if err := os.Symlink(exe, filepath.Join(d, "exe")); err != nil {
				t.Fatal(err)
			}
			_ = os.MkdirAll(filepath.Join(d, "ns"), 0o755)
			_ = os.Symlink("mnt:[4026531841]", filepath.Join(d, "ns", "mnt"))
		}
	}
	mk("1", "systemd", "0", "/usr/lib/systemd/systemd")
	mk("42", "x", "1000", "/tmp/x (deleted)")
	mk("7", "kthreadd", "0", "")
	_ = os.MkdirAll(filepath.Join(root, "self"), 0o755)

	_, _, dir2 := start(t, http.NotFoundHandler(), func(s *Server) { s.ProcRoot = root })
	resp, err := unixClient(filepath.Join(dir2, "host.sock")).Get("http://broker/procs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	for _, want := range []string{"1\t0\tsystemd\t/usr/lib/systemd/systemd\tmnt:[4026531841]\t\n", "42\t1000\tx\t/tmp/x (deleted)\tmnt:[4026531841]\t\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if strings.Contains(body, "kthreadd") || strings.Contains(body, "secret-arg") {
		t.Errorf("listed a kernel thread or a command line:\n%s", body)
	}
}

// An interpreter's script is named, never its other arguments; inline code
// is only marked.
func TestHostNamesInterpreterScripts(t *testing.T) {
	root, fsroot := t.TempDir(), t.TempDir()
	for _, f := range []string{"tmp/a.py", "tmp/b.sh", "opt/run/c.pl", "tmp/x"} {
		_ = os.MkdirAll(filepath.Join(fsroot, filepath.Dir(f)), 0o755)
		_ = os.WriteFile(filepath.Join(fsroot, f), []byte("#"), 0o644)
	}
	mk := func(pid, exe, cwd string, argv ...string) {
		d := filepath.Join(root, pid)
		_ = os.MkdirAll(filepath.Join(d, "fd"), 0o755)
		_ = os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644)
		_ = os.Symlink(exe, filepath.Join(d, "exe"))
		_ = os.Symlink(fsroot, filepath.Join(d, "root"))
		_ = os.Symlink(cwd, filepath.Join(d, "cwd"))
	}
	mk("10", "/usr/bin/python3.9", "/", "python3", "-u", "-W", "ignore", "/tmp/a.py", "--token", "s3cret")
	mk("11", "/usr/bin/bash", "/tmp", "bash", "b.sh", "s3cret")
	mk("12", "/usr/bin/perl", "/", "perl", "-I", "/opt/lib", "/opt/run/c.pl")
	mk("13", "/usr/bin/bash", "/", "bash", "-lc", "echo s3cret")
	mk("14", "/usr/bin/python3.9", "/", "python3", "-c", "print('s3cret')")
	mk("15", "/usr/bin/coreutils", "/", "/usr/bin/coreutils", "--coreutils-prog-shebang=sleep", "/tmp/x", "3600")
	mk("16", "/usr/bin/bash", "/", "bash", "/tmp/gone.sh")
	_ = os.Symlink("/tmp/gone.sh (deleted)", filepath.Join(root, "16", "fd", "255"))
	mk("17", "/usr/bin/bash", "/", "bash", "/tmp/s3cret")
	mk("18", "/usr/sbin/sshd", "/", "sshd", "/tmp/a.py")
	mk("19", "/usr/bin/bash", "/", "bash")
	got := map[string]string{}
	for _, line := range strings.Split(string(listProcs(root)), "\n") {
		if f := strings.Split(line, "\t"); len(f) == 6 {
			got[f[0]] = f[5]
		}
	}
	want := map[string]string{"10": "/tmp/a.py", "11": "/tmp/b.sh", "12": "/opt/run/c.pl", "13": "inline", "14": "inline",
		"15": "/tmp/x", "16": "/tmp/gone.sh (deleted)", "17": "", "18": "", "19": ""}
	for pid, w := range want {
		if got[pid] != w {
			t.Errorf("pid %s script = %q, want %q", pid, got[pid], w)
		}
	}
	if strings.Contains(string(listProcs(root)), "s3cret") {
		t.Errorf("an argument leaked:\n%s", listProcs(root))
	}
}

func TestHostListsFailedUnits(t *testing.T) {
	_, dir, ran := startHost(t)
	resp, err := unixClient(filepath.Join(dir, "host.sock")).Get("http://broker/failed")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := ran.all()
	if len(got) != 1 || strings.Join(got[0], " ") != "systemctl list-units --state=failed --no-legend --plain --no-pager" {
		t.Fatalf("ran %v", got)
	}
}
