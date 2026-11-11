package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// DefaultConsoleAccount is the login account recorded console sessions use.
const DefaultConsoleAccount = "advisor"

// ensureConsoleHome creates the console account's home directory when it is
// missing, so sshd stops printing "Could not chdir to home directory" before
// every console command (cube-ai-advisor#509). It returns the directory it
// created, or "" when there was nothing to do.
func ensureConsoleHome(account string, lookup func(string) (*user.User, error)) (string, error) {
	u, err := lookup(account)
	if err != nil {
		return "", nil // no such account: no console on this node
	}
	home := filepath.Clean(u.HomeDir)
	if u.HomeDir == "" || home == "/" || !filepath.IsAbs(home) {
		return "", nil
	}
	if _, err := os.Lstat(home); err == nil {
		return "", nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("console home %s: %w", home, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return "", fmt.Errorf("console account %s: uid %q", account, u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return "", fmt.Errorf("console account %s: gid %q", account, u.Gid)
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return "", fmt.Errorf("console home %s: %w", home, err)
	}
	if err := os.Chown(home, uid, gid); err != nil {
		_ = os.Remove(home)
		return "", fmt.Errorf("console home %s: %w", home, err)
	}
	return home, nil
}
