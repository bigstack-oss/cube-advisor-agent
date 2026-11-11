package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func lookupAs(home string) func(string) (*user.User, error) {
	return func(name string) (*user.User, error) {
		if name != DefaultConsoleAccount {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{Username: name, HomeDir: home,
			Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid())}, nil
	}
}

// A missing home is created, owned by the account and private to it.
func TestEnsureConsoleHomeCreatesAMissingHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "advisor")
	got, err := ensureConsoleHome(DefaultConsoleAccount, lookupAs(home))
	if err != nil || got != home {
		t.Fatalf("ensureConsoleHome = %q, %v; want %q", got, err, home)
	}
	fi, err := os.Stat(home)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("home = %v, %v; want a 0700 directory", fi, err)
	}
}

// An existing home, an unknown account and a root home are left alone.
func TestEnsureConsoleHomeLeavesOthersAlone(t *testing.T) {
	home := t.TempDir()
	if got, err := ensureConsoleHome(DefaultConsoleAccount, lookupAs(home)); err != nil || got != "" {
		t.Fatalf("existing home: %q, %v", got, err)
	}
	if got, err := ensureConsoleHome("nobody-here", lookupAs(home)); err != nil || got != "" {
		t.Fatalf("unknown account: %q, %v", got, err)
	}
	if got, err := ensureConsoleHome(DefaultConsoleAccount, lookupAs("/")); err != nil || got != "" {
		t.Fatalf("root home: %q, %v", got, err)
	}
	failing := func(string) (*user.User, error) { return nil, errors.New("nss down") }
	if got, err := ensureConsoleHome(DefaultConsoleAccount, failing); err != nil || got != "" {
		t.Fatalf("lookup error: %q, %v", got, err)
	}
}
