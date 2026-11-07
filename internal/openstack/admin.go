package openstack

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// OpenrcPath is CubeCOS's admin credential file.
const OpenrcPath = "/etc/admin-openrc.sh"

// Openrc is the admin credential an openrc file exports.
type Openrc struct {
	AuthURL, Username, Password, Project, UserDomain, ProjectDomain, CACert string
}

// String redacts the password.
func (o Openrc) String() string {
	return fmt.Sprintf("openstack.Openrc{AuthURL:%q, Username:%q, Project:%q, Password:REDACTED}", o.AuthURL, o.Username, o.Project)
}

// GoString redacts under %#v too.
func (o Openrc) GoString() string { return o.String() }

// ReadOpenrc reads the `export OS_*=value` lines of an openrc file. It does
// not run the file.
func ReadOpenrc(path string) (Openrc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Openrc{}, err
	}
	o := Openrc{UserDomain: "Default", ProjectDomain: "Default"}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		switch strings.TrimSpace(k) {
		case "OS_AUTH_URL":
			o.AuthURL = v
		case "OS_USERNAME":
			o.Username = v
		case "OS_PASSWORD":
			o.Password = v
		case "OS_PROJECT_NAME":
			o.Project = v
		case "OS_USER_DOMAIN_NAME":
			o.UserDomain = v
		case "OS_PROJECT_DOMAIN_NAME":
			o.ProjectDomain = v
		case "OS_CACERT":
			o.CACert = v
		}
	}
	if o.AuthURL == "" || o.Username == "" || o.Password == "" || o.Project == "" {
		return Openrc{}, fmt.Errorf("openstack: %s lacks OS_AUTH_URL, OS_USERNAME, OS_PASSWORD or OS_PROJECT_NAME", path)
	}
	return o, nil
}

// ErrUnknownService is returned for a service type the catalogue lacks.
var ErrUnknownService = errors.New("no such service in the catalogue")

// Admin holds a token for the node's admin credential and the catalogue it
// came with. The openrc file is re-read on each authentication.
type Admin struct {
	Path string

	mu       sync.Mutex
	token    string
	expires  time.Time
	catalog  map[string]string // service type -> endpoint
	client   *http.Client
	clientCA string
}

// NewAdmin reads credentials from path on first use.
func NewAdmin(path string) *Admin { return &Admin{Path: path} }

// HTTP returns a client trusting the openrc's CA, if it names one.
func (a *Admin) HTTP() *http.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		a.client = &http.Client{Timeout: 90 * time.Second}
	}
	return a.client
}

func (a *Admin) setCA(path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil && a.clientCA == path {
		return nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("openstack: OS_CACERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("openstack: OS_CACERT %s holds no certificate", path)
		}
		cfg.RootCAs = pool
	}
	a.client = &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	a.clientCA = path
	return nil
}

// Invalidate drops the cached token, e.g. after a 401.
func (a *Admin) Invalidate() {
	a.mu.Lock()
	a.token = ""
	a.mu.Unlock()
}

// Endpoint returns the service's endpoint (internal before public) and a
// token to call it with.
func (a *Admin) Endpoint(ctx context.Context, service string) (string, string, error) {
	a.mu.Lock()
	ok := a.token != "" && time.Now().Before(a.expires.Add(-renewMargin))
	tok, cat := a.token, a.catalog
	a.mu.Unlock()
	if !ok {
		var err error
		if tok, cat, err = a.authenticate(ctx); err != nil {
			return "", "", err
		}
	}
	ep, found := cat[service]
	if !found {
		return "", "", ErrUnknownService
	}
	return ep, tok, nil
}

func (a *Admin) authenticate(ctx context.Context) (string, map[string]string, error) {
	o, err := ReadOpenrc(a.Path)
	if err != nil {
		return "", nil, err
	}
	if err := a.setCA(o.CACert); err != nil {
		return "", nil, err
	}
	body, _ := json.Marshal(map[string]any{"auth": map[string]any{
		"identity": map[string]any{"methods": []string{"password"}, "password": map[string]any{
			"user": map[string]any{"name": o.Username, "domain": map[string]string{"name": o.UserDomain}, "password": o.Password}}},
		"scope": map[string]any{"project": map[string]any{"name": o.Project, "domain": map[string]string{"name": o.ProjectDomain}}},
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(o.AuthURL, "/")+"/auth/tokens", bytes.NewReader(body))
	if err != nil {
		return "", nil, fmt.Errorf("openstack: build the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.HTTP().Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("openstack: reach Keystone at %s: %w", o.AuthURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("openstack: Keystone refused the admin credential (HTTP %d)", resp.StatusCode)
	}
	tok := resp.Header.Get("X-Subject-Token")
	var tr tokenResponse
	if tok == "" || json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&tr) != nil {
		return "", nil, fmt.Errorf("openstack: Keystone returned no usable token")
	}
	cat := map[string]string{}
	for _, svc := range tr.Token.Catalog {
		for _, ep := range svc.Endpoints {
			if ep.Interface == "internal" || (ep.Interface == "public" && cat[svc.Type] == "") {
				cat[svc.Type] = ep.URL
			}
		}
	}
	a.mu.Lock()
	a.token, a.expires, a.catalog = tok, tr.Token.ExpiresAt, cat
	a.mu.Unlock()
	return tok, cat, nil
}

// tokenResponse is the part of Keystone's answer this client reads.
type tokenResponse struct {
	Token struct {
		ExpiresAt time.Time `json:"expires_at"`
		Project   struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"project"`
		Catalog []struct {
			Type      string `json:"type"`
			Endpoints []struct {
				Interface string `json:"interface"`
				URL       string `json:"url"`
			} `json:"endpoints"`
		} `json:"catalog"`
	} `json:"token"`
}

// renewMargin is how long before expiry a cached token is replaced.
const renewMargin = 5 * time.Minute
