package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
)

var advisor = &url.URL{Scheme: "https", Host: "advisor.example:443"}

func envFixed(raw string) proxyFunc {
	return func(*http.Request) (*url.URL, error) {
		if raw == "" {
			return nil, nil
		}
		return url.Parse(raw)
	}
}

func resolve(t *testing.T, p proxyFunc) string {
	t.Helper()
	if p == nil {
		return ""
	}
	u, err := p(&http.Request{URL: advisor})
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		return ""
	}
	return u.String()
}

func writeProxy(t *testing.T, dir, s string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, identity.ProxyFileName), []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEgressProxy(t *testing.T) {
	for _, c := range []struct {
		name, file, env, want, line string
	}{
		{name: "none", want: "", line: "none, dialing the Advisor direct"},
		{name: "env", env: "http://env:3128", want: "http://env:3128", line: "http://env:3128 (from the environment)"},
		{name: "file wins", file: "http://file:3128\n", env: "http://env:3128", want: "http://file:3128", line: "http://file:3128 (from "},
		{name: "broken file", file: "ftp://file\n", env: "http://env:3128", want: "http://env:3128", line: "ignored, http://env:3128"},
		{name: "broken file no env", file: "ftp://file\n", want: "", line: "ignored, none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if c.file != "" {
				writeProxy(t, dir, c.file)
			}
			p, line := egressProxy(dir, advisor, envFixed(c.env))
			if got := resolve(t, p); got != c.want {
				t.Errorf("proxy = %q, want %q", got, c.want)
			}
			if !strings.Contains(line, c.line) {
				t.Errorf("line = %q, want it to contain %q", line, c.line)
			}
		})
	}
}

// The startup line must not leak proxy credentials into the journal.
func TestEgressProxyLineRedactsPassword(t *testing.T) {
	dir := t.TempDir()
	writeProxy(t, dir, "http://u:secret@file:3128")
	_, line := egressProxy(dir, advisor, nil)
	if strings.Contains(line, "secret") {
		t.Errorf("line = %q leaks the password", line)
	}
}
