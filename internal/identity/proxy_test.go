package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProxy(t *testing.T) {
	for _, c := range []struct{ in, want, err string }{
		{in: "proxy.example:3128", want: "http://proxy.example:3128"},
		{in: "http://proxy.example:3128/", want: "http://proxy.example:3128/"},
		{in: "https://proxy.example:443", want: "https://proxy.example:443"},
		{in: "http://u:secret@proxy.example:3128", want: "http://u:xxxxx@proxy.example:3128"},
		{in: "socks5://proxy.example:1080", err: "scheme"},
		{in: "http://:3128", err: "no host"},
		{in: "http://proxy.example:3128/path", err: "nothing after"},
	} {
		u, err := ParseProxy(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("ParseProxy(%q) err = %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || u.Redacted() != c.want {
			t.Errorf("ParseProxy(%q) = %v, %v; want %s", c.in, u, err, c.want)
		}
	}
}

func TestLoadProxyAbsentOrEmptyIsNone(t *testing.T) {
	dir := t.TempDir()
	if u, err := LoadProxy(dir); u != nil || err != nil {
		t.Errorf("absent: %v, %v; want none", u, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ProxyFileName), []byte(" \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if u, err := LoadProxy(dir); u != nil || err != nil {
		t.Errorf("empty: %v, %v; want none", u, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ProxyFileName), []byte("http://p:3128\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if u, err := LoadProxy(dir); err != nil || u.String() != "http://p:3128" {
		t.Errorf("set: %v, %v; want http://p:3128", u, err)
	}
}
