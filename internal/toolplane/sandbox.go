package toolplane

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// SandboxCommandArg is the one argument a sandbox tool takes: the command text.
const SandboxCommandArg = "command"

// maxSandboxCommand bounds the command text a caller may send.
const maxSandboxCommand = 4096

// sandboxHidden are paths a sandboxed command cannot see: write credentials,
// the agent's own identity, and sockets that change the system. A leading "-"
// tells systemd a missing path is not an error.
var sandboxHidden = []string{
	"/etc/ceph/ceph.client.admin.keyring", "/etc/ceph/admin.key",
	"/etc/admin-openrc.sh", "/root", "/etc/rancher", "/var/lib/rancher",
	"/etc/cube/advisor-agent", "/etc/ssh", "/etc/shadow", "/etc/gshadow",
	"/var/www/certs", "/etc/my.cnf", "/etc/my.cnf.d", "/var/lib/mysql",
	"/run/dbus", "/var/run/dbus", "/run/systemd/private",
	"/run/libvirt", "/var/run/libvirt", "/run/docker.sock", "/var/run/docker.sock",
	"/run/containerd", "/run/k3s", "/run/openvswitch", "/var/run/openvswitch", "/run/ovn",
}

// sandboxKeyrings are globs for the Ceph keyrings under /var/lib/ceph, hidden
// one by one so the rest of the OSD directories stays readable.
var sandboxKeyrings = []string{"/var/lib/ceph/*/*keyring", "/var/lib/ceph/*/*/*keyring"}

// SandboxArgv is the argv that runs command in ADR 0018's read-only sandbox:
// a transient systemd unit with a read-only filesystem, a private /tmp,
// read-only block devices, no network, only the read-only DAC capability,
// setuid ignored, and credentials and control sockets hidden. No network because CubeCOS runs Ceph with cephx off, so any
// networked read could also write; network reads are declared tools.
func SandboxArgv(command string, timeout time.Duration) []string {
	return SandboxArgvFor(command, timeout, "")
}

// SandboxBrokerDir is the broker directory bound into the sandbox (ADR 0019);
// empty means no brokers.
var SandboxBrokerDir string

// sandboxScratch are throwaway, memory-backed writable directories: tools may
// write lock files and scratch there, and the host never sees it.
var sandboxScratch = []string{"/run", "/var/support"}

// SandboxArgvFor is SandboxArgv with the run's id, passed to the brokers so
// their audit records name the run that called them.
func SandboxArgvFor(command string, timeout time.Duration, callID string) []string {
	props := []string{
		"ProtectSystem=strict",
		"ProtectHome=read-only",
		"PrivateTmp=yes",
		// Block devices are readable, never writable; other devices closed.
		"DevicePolicy=closed",
		"DeviceAllow=block-sd r",
		"DeviceAllow=block-blkext r",
		"DeviceAllow=block-device-mapper r",
		"PrivateNetwork=yes",
		"NoNewPrivileges=yes",
		// Read-only DAC bypass: root reads files owned by ceph and others.
		"CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
		"AmbientCapabilities=",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectControlGroups=yes",
		"RestrictSUIDSGID=yes",
		"Environment=HOME=/tmp",
		// No network here, so make the ceph CLI give up in seconds.
		`Environment="CEPH_ARGS=--client_mount_timeout=3"`,
		fmt.Sprintf("RuntimeMaxSec=%d", int(timeout.Seconds())),
	}
	for _, d := range sandboxScratch {
		props = append(props, "TemporaryFileSystem="+d)
	}
	// A memory-only journal lives under /run/log; keep it readable.
	props = append(props, "BindReadOnlyPaths=-/run/log")
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
	if SandboxBrokerDir != "" {
		props = append(props, "BindReadOnlyPaths="+SandboxBrokerDir)
		path = SandboxBrokerDir + "/bin:" + path
	}
	props = append(props, "Environment=PATH="+path)
	if callID != "" {
		props = append(props, "Environment=ADVISOR_CALL_ID="+callID)
	}
	hidden := append([]string(nil), sandboxHidden...)
	for _, g := range sandboxKeyrings {
		m, _ := filepath.Glob(g)
		hidden = append(hidden, m...)
	}
	for _, p := range hidden {
		props = append(props, "InaccessiblePaths=-"+p)
	}
	argv := []string{"systemd-run", "--pipe", "--wait", "--quiet", "--collect", "--service-type=exec"}
	for _, p := range props {
		argv = append(argv, "-p", p)
	}
	return append(argv, "--", "/bin/bash", "-c", command)
}

// validateSandbox checks a sandbox entry: read impact only, no argv of its own.
func (t Tool) validateSandbox() error {
	if t.Impact != ImpactRead {
		return fmt.Errorf("tool %q is a sandbox tool and must be ImpactRead; the sandbox is what makes a free-form command a read", t.Name)
	}
	if len(t.Params) > 0 {
		return fmt.Errorf("tool %q is a sandbox tool and takes only %q", t.Name, SandboxCommandArg)
	}
	return nil
}

// sandboxCommand extracts and checks the command text.
func sandboxCommand(args map[string]string) (string, error) {
	for k := range args {
		if k != SandboxCommandArg {
			return "", fmt.Errorf("unexpected argument %q", k)
		}
	}
	cmd := args[SandboxCommandArg]
	switch {
	case strings.TrimSpace(cmd) == "":
		return "", errors.New("argument \"command\" is required")
	case len(cmd) > maxSandboxCommand:
		return "", fmt.Errorf("command is %d bytes; at most %d", len(cmd), maxSandboxCommand)
	case strings.ContainsRune(cmd, 0) || !utf8.ValidString(cmd):
		return "", errors.New("command must be valid text")
	}
	return cmd, nil
}

// newCallID names one sandbox run, so broker audit records can point at it.
func newCallID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// withCall copies args with the run's id added under "call".
func withCall(args map[string]string, id string) map[string]string {
	out := make(map[string]string, len(args)+1)
	for k, v := range args {
		out[k] = v
	}
	out["call"] = id
	return out
}
