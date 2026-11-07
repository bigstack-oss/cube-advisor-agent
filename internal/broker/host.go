package broker

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// unitName is a systemd unit name: letters, digits and @._:- only, so it
// can never be read as an option or a second argument.
var unitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)

// unitProps are the unit properties the host broker reports.
const unitProps = "Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestamp"

// host serves fixed views of the host the sandbox cannot see: its listening
// sockets (the sandbox has no network namespace of its own to look at), its
// processes' executables (the sandbox may not resolve /proc/PID/exe), the
// failed units and one unit's state (systemd's socket is hidden).
func (s *Server) host(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	args := map[string]string{"path": r.URL.Path}
	refuse := func(code int, why string) {
		s.record(r, "broker:host", args, false, why, started, 0)
		http.Error(w, why, code)
	}
	if r.Method != http.MethodGet {
		refuse(http.StatusMethodNotAllowed, "only GET is served")
		return
	}
	if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		refuse(http.StatusBadRequest, "malformed query: "+err.Error())
		return
	}
	var name string
	var argv []string
	switch r.URL.Path {
	case "/sockets":
		name, argv = "ss", []string{"-H", "-l", "-t", "-u", "-n", "-p"}
		if p := r.URL.Query().Get("port"); p != "" {
			args["port"] = p
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
				refuse(http.StatusBadRequest, "port must be a number from 1 to 65535")
				return
			}
			argv = append(argv, "sport", "=", ":"+p)
		}
	case "/procs":
		s.record(r, "broker:host", args, true, "", started, 0)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(listProcs(s.ProcRoot))
		return
	case "/failed":
		name, argv = "systemctl", []string{"list-units", "--state=failed", "--no-legend", "--plain", "--no-pager"}
	case "/unit":
		u := r.URL.Query().Get("name")
		args["unit"] = u
		if !unitName.MatchString(u) {
			refuse(http.StatusBadRequest, "unit name must match "+unitName.String())
			return
		}
		name, argv = "systemctl", []string{"show", "--no-pager", "-p", unitProps, "--", u}
	default:
		refuse(http.StatusNotFound, "only /sockets, /procs, /failed and /unit?name=UNIT are served")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), CallTimeout)
	defer cancel()
	run := s.HostRun
	if run == nil {
		run = LocalHostRun
	}
	out, errOut, err := run(ctx, name, argv)
	out = trimLines(out)
	if len(out) > MaxResponse {
		out = append(out[:MaxResponse], fmt.Sprintf("\n[broker: answer cut at %d bytes]\n", MaxResponse)...)
	}
	reason, code := "", http.StatusOK
	if err != nil {
		reason, code = err.Error(), http.StatusBadGateway
		out = append(out, errOut...)
	}
	s.record(r, "broker:host", args, true, reason, started, len(out))
	w.WriteHeader(code)
	_, _ = w.Write(out)
}

// trimLines drops the column padding ss adds to every line.
func trimLines(b []byte) []byte {
	lines := bytes.Split(b, []byte("\n"))
	for i, l := range lines {
		lines[i] = bytes.TrimRight(l, " \t")
	}
	return bytes.Join(lines, []byte("\n"))
}

// LocalHostRun runs one of the host broker's fixed commands without a shell.
func LocalHostRun(ctx context.Context, name string, args []string) ([]byte, []byte, error) {
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// listProcs reports every process as
// "pid<TAB>uid<TAB>comm<TAB>exe<TAB>mntns<TAB>script", exe being
// /proc/PID/exe's target (a deleted file keeps its " (deleted)" suffix; a
// kernel thread has none), mntns its mount namespace, so a reader can tell a
// container's paths from the host's, and script the file an interpreter runs
// (see scriptOf). Never the command line, which can carry credentials.
func listProcs(root string) []byte {
	if root == "" {
		root = "/proc"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return []byte("error: " + err.Error() + "\n")
	}
	var b bytes.Buffer
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join(root, pid, "exe"))
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join(root, pid, "comm"))
		uid := ""
		if st, err := os.ReadFile(filepath.Join(root, pid, "status")); err == nil {
			for _, line := range strings.Split(string(st), "\n") {
				if f := strings.Fields(line); len(f) > 1 && f[0] == "Uid:" {
					uid = f[1]
					break
				}
			}
		}
		ns, _ := os.Readlink(filepath.Join(root, pid, "ns", "mnt"))
		script := scriptOf(filepath.Join(root, pid), exe)
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\n", pid, uid, strings.TrimSpace(string(comm)), exe, ns, script)
		if b.Len() > MaxResponse {
			b.WriteString("[broker: answer cut]\n")
			break
		}
	}
	return b.Bytes()
}

// interpreter matches the executables that run a script named on their
// command line, and the letters of the options that make them run code
// given inline or on stdin instead.
var interpreters = []struct {
	name   *regexp.Regexp
	inline string
}{
	{regexp.MustCompile(`^(ba|da|z|k|a)?sh$`), "cs"},
	{regexp.MustCompile(`^python[0-9.]*$`), "cm"},
	{regexp.MustCompile(`^perl[0-9.]*$`), "eE"},
	{regexp.MustCompile(`^ruby[0-9.]*$`), "e"},
	{regexp.MustCompile(`^(node|nodejs)$`), "ep"},
	{regexp.MustCompile(`^php[0-9.]*$`), "r"},
	{regexp.MustCompile(`^coreutils$`), ""},
}

// valueOpts take their value as the next argument.
var valueOpts = map[string]bool{"-W": true, "-X": true, "-o": true, "-O": true, "+O": true, "+o": true,
	"-I": true, "-r": true, "--require": true, "-d": true, "--rcfile": true, "--init-file": true}

// scriptOf names the file an interpreter process runs: "inline" for code
// given on the command line or stdin, else the first non-option argument,
// made absolute against the process's working directory, and only when that
// is a file the process can see (" (deleted)" when it holds it open but it
// is gone). Empty for any other process. No other argument is read out.
func scriptOf(dir, exe string) string {
	base := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	inline := ""
	found := false
	for _, in := range interpreters {
		if in.name.MatchString(base) {
			inline, found = in.inline, true
			break
		}
	}
	if !found {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		return ""
	}
	argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	arg := ""
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			if i+1 < len(argv) {
				arg = argv[i+1]
			}
			break
		}
		if a == "-" {
			return "inline"
		}
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
			if !strings.HasPrefix(a, "--") && strings.ContainsAny(strings.TrimLeft(a[1:], "-"), inline) && inline != "" {
				return "inline"
			}
			if valueOpts[a] {
				i++
			}
			continue
		}
		arg = a
		break
	}
	if arg == "" || strings.ContainsAny(arg, "\t\n") {
		return ""
	}
	if !filepath.IsAbs(arg) {
		cwd, err := os.Readlink(filepath.Join(dir, "cwd"))
		if err != nil {
			return ""
		}
		arg = filepath.Join(cwd, arg)
	}
	arg = filepath.Clean(arg)
	if st, err := os.Stat(filepath.Join(dir, "root", arg)); err == nil && st.Mode().IsRegular() {
		return arg
	}
	fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
	for _, fd := range fds {
		if t, _ := os.Readlink(filepath.Join(dir, "fd", fd.Name())); t == arg+" (deleted)" {
			return t
		}
	}
	return ""
}
