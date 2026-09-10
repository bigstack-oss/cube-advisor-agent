package openstack

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// renewMargin is how long before expiry a cached token is replaced.
//
// A token that expires between the check and the request is a create that
// fails for a reason the model cannot interpret and a person has to go and
// find. Five minutes is far longer than any request this client makes and far
// shorter than Keystone's default hour.
const renewMargin = 5 * time.Minute

// Compute posts to the cluster's nova.
//
// It implements the tool plane's Poster: it owns the endpoint, the credential
// and the TLS trust, so none of them reach the allowlist, the audit log or the
// model. The path it is given is nova-relative — "/servers" — and this type
// supplies everything in front of it.
type Compute struct {
	cred Credential
	http *http.Client

	mu       sync.Mutex
	token    string
	expires  time.Time
	endpoint string
}

// NewCompute builds a client. It performs no I/O: the first call authenticates,
// so an agent whose Keystone is briefly down still starts, and an operator
// who has just written a credential does not have to restart to use it.
func NewCompute(c Credential) (*Compute, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CACertPEM)) {
			return nil, fmt.Errorf("openstack: ca_cert_pem holds no usable certificate")
		}
		tlsCfg.RootCAs = pool
	}
	return &Compute{
		cred: c,
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			// Below the tool's own 60s timeout, which the tool plane applies
			// to the context; this is the backstop for a socket that never
			// answers at all.
			Timeout: 90 * time.Second,
		},
	}, nil
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

// authenticate redeems the application credential and caches the token and the
// compute endpoint it came with.
//
// The endpoint comes from the catalog rather than from configuration, which is
// how every OpenStack client finds a service and is why the allowlist writes
// only "/servers". An operator who moves nova, changes its port or puts it
// behind a different VIP changes nothing here.
func (c *Compute) authenticate(ctx context.Context) (string, string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.expires.Add(-renewMargin)) {
		tok, ep := c.token, c.endpoint
		c.mu.Unlock()
		return tok, ep, nil
	}
	c.mu.Unlock()

	body, err := json.Marshal(map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"application_credential"},
				"application_credential": map[string]any{
					"id":     c.cred.ID,
					"secret": c.cred.Secret,
				},
			},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("openstack: build the token request: %w", err)
	}

	url := strings.TrimSuffix(c.cred.AuthURL, "/") + "/auth/tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("openstack: build the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// The URL is the operator's own and safe to name; the body is not,
		// and is not included.
		return "", "", fmt.Errorf("openstack: reach Keystone at %s: %w", c.cred.AuthURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// No body: a Keystone error can echo the request, and the request
		// holds the secret.
		return "", "", fmt.Errorf("openstack: Keystone refused the application credential (HTTP %d); "+
			"check that it exists and has not been revoked", resp.StatusCode)
	}

	// The token is a header, not a body field.
	tok := resp.Header.Get("X-Subject-Token")
	if tok == "" {
		return "", "", fmt.Errorf("openstack: Keystone returned no token")
	}

	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", "", fmt.Errorf("openstack: Keystone's response is not the shape this client reads")
	}

	// The scope check. An application credential is scoped where it was
	// created, not where configuration claims — so if the two disagree, the
	// operator's belief about which project this agent can create in is
	// wrong, and the safe reading is to refuse rather than to create
	// somewhere unexpected.
	if got := tr.Token.Project.Name; got != "" && got != c.cred.Project {
		return "", "", fmt.Errorf("openstack: the credential is scoped to project %q but the configuration says %q; "+
			"refusing rather than creating in a project nobody chose", got, c.cred.Project)
	}

	endpoint := computeEndpoint(tr)
	if endpoint == "" {
		return "", "", fmt.Errorf("openstack: the Keystone catalog names no compute service; " +
			"this cluster's nova is not registered, or the credential's roles cannot see it")
	}

	c.mu.Lock()
	c.token, c.expires, c.endpoint = tok, tr.Token.ExpiresAt, endpoint
	c.mu.Unlock()
	return tok, endpoint, nil
}

// computeEndpoint picks the compute service URL from the catalog.
//
// Internal before public: both are on the management network, and the internal
// interface is the one a service on the cluster is meant to use. A deployment
// that registers only one gets that one.
func computeEndpoint(tr tokenResponse) string {
	var public string
	for _, svc := range tr.Token.Catalog {
		if svc.Type != "compute" {
			continue
		}
		for _, ep := range svc.Endpoints {
			switch ep.Interface {
			case "internal":
				return ep.URL
			case "public":
				public = ep.URL
			}
		}
	}
	return public
}

// Post sends a write to nova and returns up to maxBytes of the response.
//
// idempotencyKey travels as a header for a server that honours one. nova does
// not, today: it permits duplicate server names and has no create-once
// semantics on this path, so the header is sent because a proxy or a future
// nova may act on it and costs nothing if nothing does. The duplicate
// suppression that actually holds is the tool plane's ledger, which does not
// depend on this.
func (c *Compute) Post(ctx context.Context, path string, body []byte, idempotencyKey string, maxBytes int) ([]byte, error) {
	tok, endpoint, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	url := strings.TrimSuffix(endpoint, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("openstack: build the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", tok)
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openstack: reach the compute service: %w", err)
	}
	defer resp.Body.Close()

	out, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)))
	if resp.StatusCode >= 300 {
		// nova's error bodies describe the request, not the credential, and
		// are what an operator needs to see: "flavor not found" is the whole
		// diagnosis. Truncated to the same budget as a success.
		return out, fmt.Errorf("openstack: the compute service refused the request (HTTP %d): %s",
			resp.StatusCode, strings.TrimSpace(string(out)))
	}
	if readErr != nil {
		return nil, fmt.Errorf("openstack: read the response: %w", readErr)
	}
	return out, nil
}
