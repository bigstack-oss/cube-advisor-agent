package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/openstack"
)

// OpenStackSource resolves a catalogue service to its endpoint and a token.
// openstack.Admin satisfies it.
type OpenStackSource interface {
	Endpoint(ctx context.Context, service string) (endpoint, token string, err error)
	Invalidate()
	HTTP() *http.Client
}

var (
	osService = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	// osPath allows plain segments only: no %, ;, \, empty, or dot-only ones.
	osPath = regexp.MustCompile(`^(/[A-Za-z0-9_~:@,=+.-]+)+/?$`)
)

// osDeniedServices hold secrets or user data in every answer.
var osDeniedServices = map[string]bool{"key-manager": true, "object-store": true, "s3": true}

// osDeniedSegments are path segments (lower case) whose answers carry
// secrets, keys or user data.
var osDeniedSegments = map[string]bool{
	"credentials": true, "application_credentials": true, "os-oauth1": true, "os-oauth2": true, // keystone
	"os-keypairs": true, "os-server-password": true, "os-console-auth-tokens": true, // nova
	"secrets": true, "payload": true, // barbican
	"file":        true,                // glance image data
	"environment": true, "files": true, // heat
	"share-access-rules": true, "security-services": true, // manila
	"ipsec-site-connections": true, // neutron vpnaas
	"tsigkeys":               true, // designate
	"vendor_passthru":        true, // ironic driver calls
}

// CheckOpenStackPath validates one os-ro request and returns its path and
// re-encoded query.
func CheckOpenStackPath(service, target string) (string, string, error) {
	if !osService.MatchString(service) {
		return "", "", fmt.Errorf("service must be a catalogue type matching %s", osService)
	}
	if osDeniedServices[service] {
		return "", "", fmt.Errorf("service %s is not served: its answers carry secrets or user data", service)
	}
	p, rawQuery, _ := strings.Cut(target, "?")
	if !osPath.MatchString(p) {
		return "", "", fmt.Errorf("path must be /segment/... of letters, digits and _~:@,=+.-")
	}
	if err := checkSegments(p); err != nil {
		return "", "", err
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", "", fmt.Errorf("malformed query: %v", err)
	}
	return p, q.Encode(), nil
}

func checkSegments(p string) error {
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if strings.Trim(seg, ".") == "" || strings.Contains(seg, "..") {
			return fmt.Errorf("path segment %q is not allowed", seg)
		}
		if osDeniedSegments[strings.ToLower(seg)] {
			return fmt.Errorf("%s is not served: it returns secrets", seg)
		}
	}
	return nil
}

// joinEndpoint puts p under the endpoint's path, unless p already starts
// with it (so both /servers and /v2.1/servers work).
func joinEndpoint(endpoint, p, query string) (*url.URL, error) {
	ep, err := url.Parse(endpoint)
	if err != nil || ep.Host == "" {
		return nil, fmt.Errorf("bad catalogue endpoint")
	}
	base := strings.TrimSuffix(ep.Path, "/")
	if base != "" && p != base && !strings.HasPrefix(p, base+"/") {
		p = base + p
	}
	if err := checkSegments(p); err != nil {
		return nil, err
	}
	return &url.URL{Scheme: ep.Scheme, Host: ep.Host, Path: p, RawQuery: query}, nil
}

// openstack forwards GET /get?service=TYPE&path=/PATH?QUERY to the service's
// endpoint with the admin token. No client header is forwarded, so answers
// stay at the base microversion.
func (s *Server) openstack(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	q := r.URL.Query()
	args := map[string]string{"method": r.Method, "service": q.Get("service"), "path": q.Get("path")}
	refuse := func(code int, why string) {
		s.record(r, "broker:os", args, false, why, started, 0)
		http.Error(w, why, code)
	}
	if r.Method != http.MethodGet {
		refuse(http.StatusMethodNotAllowed, "only GET is forwarded")
		return
	}
	if r.URL.Path != "/get" {
		refuse(http.StatusNotFound, "only /get?service=TYPE&path=PATH is served")
		return
	}
	if s.OpenStack == nil {
		refuse(http.StatusServiceUnavailable, "no OpenStack credential on this node")
		return
	}
	p, query, err := CheckOpenStackPath(q.Get("service"), q.Get("path"))
	if err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), CallTimeout)
	defer cancel()
	var resp *http.Response
	for attempt := 0; attempt < 2; attempt++ {
		endpoint, token, err := s.OpenStack.Endpoint(ctx, q.Get("service"))
		if err != nil {
			code := http.StatusBadGateway
			if errors.Is(err, openstack.ErrUnknownService) {
				code = http.StatusNotFound
			}
			refuse(code, err.Error())
			return
		}
		u, err := joinEndpoint(endpoint, p, query)
		if err != nil {
			refuse(http.StatusForbidden, err.Error())
			return
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		req.Header.Set("X-Auth-Token", token)
		req.Header.Set("Accept", "application/json")
		resp, err = s.OpenStack.HTTP().Do(req)
		if err != nil {
			refuse(http.StatusBadGateway, "openstack: "+err.Error())
			return
		}
		if resp.StatusCode != http.StatusUnauthorized || attempt == 1 {
			break
		}
		resp.Body.Close()
		s.OpenStack.Invalidate()
	}
	defer resp.Body.Close()
	body, truncated := readCapped(resp.Body)
	reason := ""
	if truncated {
		reason = fmt.Sprintf("answer cut at %d bytes", MaxResponse)
	}
	s.record(r, "broker:os", args, true, reason, started, len(body))
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
	if truncated {
		fmt.Fprintf(w, "\n[broker: answer cut at %d bytes]\n", MaxResponse)
	}
}
