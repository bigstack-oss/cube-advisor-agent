package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConsoleCAFileName is where RecordConsoleCA writes, inside the identity dir.
const ConsoleCAFileName = "console-ca.pub"

// TrustedConsoleCAPath is the CA sshd trusts for console sessions. CubeCOS
// creates it at enrolment, and only when the token granted console access.
const TrustedConsoleCAPath = "/etc/ssh/console-ca/cube-advisor.pub"

// ValidConsoleCALine reports whether line is one SSH public key in
// authorized-keys form whose blob names the same key type as its first field.
func ValidConsoleCALine(line string) error {
	if strings.ContainsAny(line, "\r\n\x00") {
		return fmt.Errorf("identity: console CA is not one line")
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		return fmt.Errorf("identity: console CA is not an authorized-keys line")
	}
	if !strings.HasPrefix(f[0], "ssh-") && !strings.HasPrefix(f[0], "ecdsa-") && !strings.HasPrefix(f[0], "sk-") {
		return fmt.Errorf("identity: console CA has unknown key type %q", f[0])
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 4 {
		return fmt.Errorf("identity: console CA key is not base64")
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != f[0] {
		return fmt.Errorf("identity: console CA key does not match its type %q", f[0])
	}
	return nil
}

// RecordConsoleCA writes the Advisor's console CA beside the identity. Public
// material, so world-readable; unchanged content is left alone.
func RecordConsoleCA(dir, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if err := ValidConsoleCALine(line); err != nil {
		return err
	}
	_, err := replaceFile(filepath.Join(dir, ConsoleCAFileName), line+"\n", true)
	return err
}

// RotateTrustedConsoleCA replaces the CA sshd trusts with line, but only when
// path already exists: console access is granted at enrolment, never here.
// sshd reads the file per authentication, so no reload is needed.
func RotateTrustedConsoleCA(path, line string) (changed bool, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return false, nil
	}
	if err := ValidConsoleCALine(line); err != nil {
		return false, err
	}
	return replaceFile(path, line+"\n", false)
}

// replaceFile atomically writes content at path (0644) if it differs. With
// create false, a missing path is left missing.
func replaceFile(path, content string, create bool) (bool, error) {
	old, err := os.ReadFile(path)
	switch {
	case err == nil && bytes.Equal(old, []byte(content)):
		return false, nil
	case os.IsNotExist(err) && !create:
		return false, nil
	case err != nil && !os.IsNotExist(err):
		return false, fmt.Errorf("identity: read %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return false, fmt.Errorf("identity: write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return false, fmt.Errorf("identity: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("identity: write %s: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return false, fmt.Errorf("identity: chmod %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("identity: install %s: %w", path, err)
	}
	return true, nil
}
