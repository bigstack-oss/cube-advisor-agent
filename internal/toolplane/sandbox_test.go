package toolplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestShellReadRunsTheCommandInsideTheSandbox(t *testing.T) {
	r, rec, argv := newTestRegistry(t)
	cmd := "ps -eo pid,rss,comm --sort=-rss | head -5"
	if _, err := r.Call(context.Background(), "shell_read", map[string]string{"command": cmd}); err != nil {
		t.Fatalf("Call: %v", err)
	}
	got := *argv
	if got[0] != "systemd-run" {
		t.Fatalf("argv[0] = %q; the command must run through systemd-run", got[0])
	}
	tail := got[len(got)-4:]
	if strings.Join(tail, " ") != "-- /bin/bash -c "+cmd {
		t.Errorf("argv tail = %q; the command must be the last argument of bash -c", tail)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{
		"ProtectSystem=strict", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "PrivateTmp=yes",
		"InaccessiblePaths=-/etc/ceph/ceph.client.admin.keyring", "InaccessiblePaths=-/etc/cube/advisor-agent",
		"InaccessiblePaths=-/run/dbus", "PrivateNetwork=yes",
		"DevicePolicy=closed", "DeviceAllow=block-sd r", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("sandbox argv lacks %q", want)
		}
	}
	calls := rec.snapshot()
	if len(calls) != 1 || !calls[0].Allowed || calls[0].Args["command"] != cmd {
		t.Errorf("audit = %+v; the command must be recorded", calls)
	}
}

func TestShellReadRefusesBadArguments(t *testing.T) {
	r, _, argv := newTestRegistry(t)
	for name, args := range map[string]map[string]string{
		"no command":     {},
		"blank":          {"command": "  "},
		"extra argument": {"command": "uptime", "unit": "x"},
		"too long":       {"command": strings.Repeat("a", maxSandboxCommand+1)},
		"nul byte":       {"command": "uptime\x00rm"},
	} {
		*argv = nil
		if _, err := r.Call(context.Background(), "shell_read", args); !errors.Is(err, ErrBadArgument) {
			t.Errorf("%s: err = %v, want a bad-argument refusal", name, err)
		}
		if *argv != nil {
			t.Errorf("%s: something ran", name)
		}
	}
}

func TestSandboxBoundsItsOwnRuntime(t *testing.T) {
	if !strings.Contains(strings.Join(SandboxArgv("x", 45*time.Second), " "), "RuntimeMaxSec=45") {
		t.Error("the unit does not carry the tool's timeout")
	}
}

func TestASandboxedCommandsFailureIsItsResult(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	r.run = func(ctx context.Context, argv []string, maxBytes int) ([]byte, error) {
		return []byte("lsblk: /dev/sdz: not a block device"), errors.New("exit status 32")
	}
	out, err := r.Call(context.Background(), "shell_read", map[string]string{"command": "lsblk /dev/sdz"})
	if err != nil {
		t.Fatalf("Call: %v; a command's own failure must come back as output", err)
	}
	if !strings.Contains(string(out), "not a block device") || !strings.Contains(string(out), "exit status 32") {
		t.Errorf("output = %q; want the command's output and its exit status", out)
	}
}

func TestSandboxHidesKeyringsButNotOSDDirs(t *testing.T) {
	joined := strings.Join(SandboxArgv("true", time.Minute), " ")
	if strings.Contains(joined, "InaccessiblePaths=-/var/lib/ceph ") {
		t.Error("/var/lib/ceph is hidden whole; only its keyrings should be")
	}
	if !strings.Contains(joined, `CEPH_ARGS=--client_mount_timeout=3`) {
		t.Error("the ceph CLI is not told to give up quickly")
	}
}

func TestSandboxBindsBrokersAndThrowawayScratch(t *testing.T) {
	old := SandboxBrokerDir
	SandboxBrokerDir = "/run/cube-advisor-agent/broker"
	t.Cleanup(func() { SandboxBrokerDir = old })
	argv := strings.Join(SandboxArgvFor("prom query up", time.Minute, "abc"), " ")
	for _, want := range []string{
		"TemporaryFileSystem=/run", "TemporaryFileSystem=/var/support", "BindReadOnlyPaths=-/run/log",
		"BindReadOnlyPaths=/run/cube-advisor-agent/broker",
		"Environment=PATH=/run/cube-advisor-agent/broker/bin:", "Environment=ADVISOR_CALL_ID=abc",
		"PrivateNetwork=yes",
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("sandbox lacks %s", want)
		}
	}
	if strings.Contains(argv, "TemporaryFileSystem=/var/log") {
		t.Error("/var/log must stay the real, read-only logs")
	}
}
