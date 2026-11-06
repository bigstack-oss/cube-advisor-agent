package broker

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// unitName is a systemd unit name: letters, digits and @._:- only, so it
// can never be read as an option or a second argument.
var unitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)

// unitProps are the unit properties the host broker reports.
const unitProps = "Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestamp"

// host serves two fixed views of the host the sandbox cannot see: its
// listening sockets (the sandbox has no network namespace of its own to
// look at) and one unit's state (systemd's socket is hidden).
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
	case "/unit":
		u := r.URL.Query().Get("name")
		args["unit"] = u
		if !unitName.MatchString(u) {
			refuse(http.StatusBadRequest, "unit name must match "+unitName.String())
			return
		}
		name, argv = "systemctl", []string{"show", "--no-pager", "-p", unitProps, "--", u}
	default:
		refuse(http.StatusNotFound, "only /sockets and /unit?name=UNIT are served")
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
