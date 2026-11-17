package main

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/bigstack-oss/cube-advisor-agent/internal/identity"
)

// proxyFunc picks a request's egress proxy, as http.Transport.Proxy.
type proxyFunc = func(*http.Request) (*url.URL, error)

// egressProxy picks how the tunnel reaches target: the proxy file in dir,
// else env (HTTPS_PROXY/NO_PROXY), else direct. A malformed file is reported
// and skipped. The line says which, for the startup log.
func egressProxy(dir string, target *url.URL, env proxyFunc) (proxyFunc, string) {
	path := filepath.Join(dir, identity.ProxyFileName)
	u, err := identity.LoadProxy(dir)
	if err == nil && u != nil {
		return http.ProxyURL(u), fmt.Sprintf("egress proxy: %s (from %s)", u.Redacted(), path)
	}
	prefix := "egress proxy: "
	if err != nil {
		prefix = fmt.Sprintf("egress proxy: %v; ignored, ", err)
	}
	if env != nil {
		eu, eerr := env(&http.Request{URL: target})
		if eerr != nil {
			return nil, fmt.Sprintf("%senvironment: %v; dialing the Advisor direct", prefix, eerr)
		}
		if eu != nil {
			return env, fmt.Sprintf("%s%s (from the environment)", prefix, eu.Redacted())
		}
	}
	return env, prefix + "none, dialing the Advisor direct"
}
