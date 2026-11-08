package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// PeerTimeout bounds one read on another node, connection included.
const PeerTimeout = 90 * time.Second

// nodesTTL is how long the cluster's node list is cached.
const nodesTTL = time.Minute

// hostName is a cluster node name as the node list holds it; it can never
// be read as an ssh option.
var hostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// sshArgs are the options of a peer read, before the destination. They match
// the node's own ssh_config for root, without a shared control socket.
var sshArgs = []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
	"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
	"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
	"-o", "ControlPath=none", "-o", "LogLevel=ERROR"}

// SSHCommand is the argv of a peer read: the fixed script goes on stdin, and
// args are only the view's validated arguments.
func SSHCommand(node string, args []string) []string {
	argv := append([]string{"ssh"}, sshArgs...)
	argv = append(argv, "root@"+node, "sh", "-s", "--")
	for _, a := range args {
		argv = append(argv, "'"+a+"'")
	}
	return argv
}

// errUnreachable marks a peer read that never reached the node.
var errUnreachable = errors.New(tunnelproto.PeerUnreachable)

// RunScript runs a fixed view script with sh on this node (node "") or on
// node over SSH, its output capped at MaxResponse. A failed connection
// returns errUnreachable.
func RunScript(ctx context.Context, node, script string, args []string) ([]byte, []byte, error) {
	var argv []string
	if node == "" {
		argv = append([]string{"sh", "-s", "--"}, args...)
	} else {
		argv = SSHCommand(node, args)
	}
	out, errOut := &capped{max: MaxResponse}, &capped{max: 4 << 10}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	var ee *exec.ExitError
	if node != "" && errors.As(err, &ee) && ee.ExitCode() == 255 {
		err = errUnreachable
	}
	return out.bytes(), errOut.buf.Bytes(), err
}

// capped keeps the first max bytes written and notes the cut. It has no
// ReadFrom, so exec's copy goes through Write.
type capped struct {
	buf bytes.Buffer
	max int
	cut bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.cut = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capped) bytes() []byte {
	if c.cut {
		return append(c.buf.Bytes(), fmt.Sprintf("\n[broker: answer cut at %d bytes]\n", c.max)...)
	}
	return c.buf.Bytes()
}

// LocalNodes reads the cluster's node names from CubeCOS's node list.
func LocalNodes(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "cubectl", "node", "list", "-j").Output()
	if err != nil {
		return nil, fmt.Errorf("cubectl node list: %w", err)
	}
	return ParseNodeList(out)
}

// ParseNodeList takes the hostnames from `cubectl node list -j`.
func ParseNodeList(b []byte) ([]string, error) {
	var nodes []struct {
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(b, &nodes); err != nil {
		return nil, fmt.Errorf("node list: %w", err)
	}
	var out []string
	for _, n := range nodes {
		if hostName.MatchString(n.Hostname) {
			out = append(out, n.Hostname)
		}
	}
	return out, nil
}

// clusterNodes is the cached node list.
func (s *Server) clusterNodes(ctx context.Context) ([]string, error) {
	s.nodesMu.Lock()
	defer s.nodesMu.Unlock()
	if s.nodes != nil && time.Since(s.nodesAt) < nodesTTL {
		return s.nodes, nil
	}
	f := s.Nodes
	if f == nil {
		f = LocalNodes
	}
	n, err := f(ctx)
	if err != nil {
		return nil, err
	}
	s.nodes, s.nodesAt = n, time.Now()
	return n, nil
}

// nodesView lists the cluster's nodes, this one marked "self".
func (s *Server) nodesView(ctx context.Context) ([]byte, error) {
	nodes, err := s.clusterNodes(ctx)
	if err != nil {
		return nil, err
	}
	hn := s.Hostname
	if hn == nil {
		hn = os.Hostname
	}
	self, _ := hn()
	short := strings.SplitN(self, ".", 2)[0]
	var b bytes.Buffer
	for _, n := range nodes {
		if n == self || n == short {
			fmt.Fprintf(&b, "%s\tself\n", n)
		} else {
			fmt.Fprintf(&b, "%s\n", n)
		}
	}
	return b.Bytes(), nil
}

// PeerReadsAvailable says whether this node can serve peer reads.
func PeerReadsAvailable() bool {
	for _, c := range []string{"cubectl", "ssh"} {
		if _, err := exec.LookPath(c); err != nil {
			return false
		}
	}
	return true
}

// Fixed view scripts. Each runs with sh, on this node or on a peer, with
// only the view's validated arguments as $1.
var viewScripts = map[string]string{
	"sockets": `exec ss -H -l -t -u -n -p ${1:+sport = :$1}`,
	"failed":  `exec systemctl list-units --state=failed --no-legend --plain --no-pager`,
	"unit":    `exec systemctl show --no-pager -p ` + unitProps + ` -- "$1"`,
	"procs":   "exec python3 - <<'PY'\n" + procsPy + "PY\n",
	// errlog counts error-priority journal lines per day back from now
	// (day 0 is the last 24 h) and unit, over the last 7 days.
	"errlog": `now=$(date +%s); journalctl -p err --since "-7 days" -o short-unix --no-pager -q 2>/dev/null |
awk -v now="$now" '{ split($1, t, "."); d = int((now - t[1]) / 86400); u = $3; sub(/\[[0-9]+\]:?$/, "", u); sub(/:$/, "", u); c[d "\t" u]++ }
END { for (k in c) print k "\t" c[k] }'; true`,
	// oom is the kernel's OOM kills over the last 25 h.
	"oom": `journalctl -k --since "-25 hours" -o short-iso --no-pager -q 2>/dev/null | grep -E 'Out of memory: Killed process|Memory cgroup out of memory: Killed process' | tail -n 50; true`,
	// logsize is df, logs over 512 MiB written in the last day, and /var/log's size.
	"logsize": `printf '##df\n'; df -P -B1M -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null
printf '\n##big\n'; find /var/log -xdev -type f -size +512M -mmin -1440 -printf '%s\t%p\n' 2>/dev/null | head -n 50
printf '\n##logdir\n'; du -sm /var/log 2>/dev/null
true`,
	// unowned is the host-namespace executables and scripts of running
	// processes that no package owns, with their inode change times, and the
	// booted firmware image's install date.
	"unowned": `p=$(python3 - <<'PY'
` + procsPy + `PY
)
ns=$(printf '%s\n' "$p" | awk -F'\t' '$1 == "1" { print $5 }')
printf '##unowned\n'
printf '%s\n' "$p" | awk -F'\t' -v ns="$ns" 'NF >= 5 && $5 == ns && $4 !~ / \(deleted\)$/ { print $4 } NF >= 6 && $5 == ns && $6 ~ /^\// && $6 !~ / \(deleted\)$/ { print $6 }' | sort -u |
  xargs -r -d '\n' rpm -qf 2>&1 | sed -n 's/^file \(.*\) is not owned by any package$/\1/p' | xargs -r -d '\n' stat -c '%Z	%n' 2>/dev/null
printf '\n##installed\n'; part=$(sed -n 's/.*BOOT_IMAGE=\/Part\([12]\)\/.*/\1/p' /proc/cmdline); [ -n "$part" ] && sed -n 's/^install_date *= *//p' /boot/grub2/info$part
true`,
}

// procsPy lists processes as listProcs does, for a node this agent does not
// run on: same columns, never a command line. Python 3.6 or later.
const procsPy = `import os, re, sys
R = sys.argv[1] if len(sys.argv) > 1 else "/proc"
INTERP = [("(ba|da|z|k|a)?sh", "cs"), ("python[0-9.]*", "cm"), ("perl[0-9.]*", "eE"), ("ruby[0-9.]*", "e"),
          ("(node|nodejs)", "ep"), ("php[0-9.]*", "r"), ("coreutils", "")]
VALUE = {"-W", "-X", "-o", "-O", "+O", "+o", "-I", "-r", "--require", "-d", "--rcfile", "--init-file"}
def link(p):
    try:
        return os.readlink(p)
    except OSError:
        return None
def read(p):
    try:
        with open(p, "rb") as f:
            return os.fsdecode(f.read())
    except OSError:
        return None
def clean(p):
    p = os.path.normpath(p)
    return "/" + p.lstrip("/") if p.startswith("//") else p
def script_of(d, exe):
    base = os.path.basename(exe[:-10] if exe.endswith(" (deleted)") else exe)
    inline = None
    for pat, opts in INTERP:
        if re.fullmatch(pat, base):
            inline = opts
            break
    if inline is None:
        return ""
    raw = read(os.path.join(d, "cmdline"))
    if raw is None:
        return ""
    argv = raw.rstrip("\0").split("\0")
    arg, i = "", 1
    while i < len(argv):
        a = argv[i]
        if a == "--":
            if i + 1 < len(argv):
                arg = argv[i + 1]
            break
        if a == "-":
            return "inline"
        if a.startswith("-") or a.startswith("+"):
            if not a.startswith("--") and inline and any(c in inline for c in a[1:].lstrip("-")):
                return "inline"
            if a in VALUE:
                i += 1
            i += 1
            continue
        arg = a
        break
    if arg == "" or "\t" in arg or "\n" in arg:
        return ""
    if not arg.startswith("/"):
        cwd = link(os.path.join(d, "cwd"))
        if cwd is None:
            return ""
        arg = os.path.join(cwd, arg)
    arg = clean(arg)
    try:
        import stat
        if stat.S_ISREG(os.stat(os.path.join(d, "root", arg.lstrip("/"))).st_mode):
            return arg
    except OSError:
        pass
    try:
        fds = os.listdir(os.path.join(d, "fd"))
    except OSError:
        fds = []
    for fd in fds:
        if link(os.path.join(d, "fd", fd)) == arg + " (deleted)":
            return arg + " (deleted)"
    return ""
out = sys.stdout.buffer
for pid in sorted(os.listdir(R)):
    if not pid.isdigit():
        continue
    d = os.path.join(R, pid)
    exe = link(os.path.join(d, "exe"))
    if exe is None:
        continue
    comm = (read(os.path.join(d, "comm")) or "").strip()
    uid = ""
    for line in (read(os.path.join(d, "status")) or "").split("\n"):
        f = line.split()
        if len(f) > 1 and f[0] == "Uid:":
            uid = f[1]
            break
    ns = link(os.path.join(d, "ns", "mnt")) or ""
    out.write(os.fsencode("\t".join([pid, uid, comm, exe, ns, script_of(d, exe)]) + "\n"))
`
