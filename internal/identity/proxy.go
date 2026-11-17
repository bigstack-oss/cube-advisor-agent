package identity

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ProxyFileName holds the egress proxy the tunnel dials through, one URL such
// as http://proxy.example:3128. It lives with the identity so a firmware
// upgrade carries it across.
const ProxyFileName = "proxy"

// LoadProxy reads the egress proxy from dir. A missing or empty file means
// none and is not an error.
func LoadProxy(dir string) (*url.URL, error) {
	path := filepath.Join(dir, ProxyFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	raw := strings.TrimSpace(string(b))
	if raw == "" {
		return nil, nil
	}
	u, err := ParseProxy(raw)
	if err != nil {
		return nil, fmt.Errorf("identity: %s: %w", path, err)
	}
	return u, nil
}

// ParseProxy accepts a proxy URL, or a bare host:port taken as http, the way
// HTTPS_PROXY is read.
func ParseProxy(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a proxy URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxy scheme %q: want http or https", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("proxy URL %q names no host", u.Redacted())
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, fmt.Errorf("proxy URL %q: want scheme://host:port and nothing after it", u.Redacted())
	}
	return u, nil
}
