// Package cubecosapi is the agent's authenticated reader for the cube-cos-api
// running on its own node.
//
// It exists because the read catalogue had nowhere to go: toolplane declared a
// CubeCOSGetter and a refusing default, and nothing in this repository ever
// implemented one, so all 21 catalogue paths answered "cube-cos-api access is
// not configured on this agent" on every cluster. That was half of the lab
// finding; the other half was that nothing wired it (ADR 0016, slice 4).
//
// The package owns the base URL, the node token and the transport. None of
// them enter toolplane, so none can reach the audit log.
package cubecosapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// NodeTokenPath is where cube-cos-api writes the node-to-node token it will
// accept, at startup, from flushDefaultNodeToken.
//
// Not configurable. The path is cube-cos-api's own constant, and an agent that
// let an operator point this elsewhere would be letting them nominate which
// secret it presents — which is the escalation the mode check on the config
// file exists to prevent, reintroduced through a second door.
const NodeTokenPath = "/var/run/cube-cos-api/node_token"

// Client reads cube-cos-api over its local HTTP listener.
//
// Authentication is the internal node-to-node path: cube-cos-api accepts a
// request carrying Node: <hostname> and Authorization: Bearer <token> when the
// token equals its own sha512(hostname + oidc client secret). It checks that
// first, before the OpenStack and OIDC paths, and it is the only one of the
// four an on-node daemon can satisfy without holding a user's credentials.
type Client struct {
	base     *url.URL
	hostname string
	http     *http.Client
	// tokenPath is fixed in production and overridden only by tests, which
	// cannot write to /var/run.
	tokenPath string
}

// String redacts. The token never lives on this struct — it is read per
// request — but the base URL identifies the customer's management network, and
// a Client reaching a log line by way of %v is the mistake this prevents.
func (c *Client) String() string {
	return fmt.Sprintf("cubecosapi.Client{base:REDACTED, hostname:%q}", c.hostname)
}

// GoString redacts under %#v too.
func (c *Client) GoString() string { return c.String() }

// New builds a client for the cube-cos-api at base.
//
// The hostname is this node's own, and must be: cube-cos-api validates the
// token against sha512 of whatever the Node header says, so the header and the
// token file have to name the same node. Reading the local token while
// claiming to be another node produces a 401, which is the correct outcome but
// a confusing one, so the header is not configurable.
func New(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("cubecosapi: base url %q: %w", base, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("cubecosapi: base url %q must be http or https", base)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("cubecosapi: base url %q has no host", base)
	}

	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("cubecosapi: hostname: %w", err)
	}

	return &Client{
		base:     u,
		hostname: host,
		// No client timeout: every Get is already bounded by the context
		// toolplane.fetch derives from the tool's own timeout, and a second
		// deadline here would either shadow that one or contradict it.
		http:      &http.Client{},
		tokenPath: NodeTokenPath,
	}, nil
}

// Get performs the authenticated read and returns at most maxBytes.
//
// Over-long responses come back truncated with ErrOutputTruncated, which is the
// contract toolplane's command runner already follows: the caller applies the
// marker, so there is one place that decides what a cut looks like and
// tool-0010 measures whether the model reports it.
func (c *Client) Get(ctx context.Context, path string, maxBytes int) ([]byte, error) {
	token, err := c.token()
	if err != nil {
		return nil, err
	}

	ref, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("cubecosapi: path %q: %w", path, err)
	}
	if ref.IsAbs() || ref.Host != "" {
		return nil, fmt.Errorf("cubecosapi: path %q must be relative to the api", path)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.ResolveReference(ref).String(), nil)
	if err != nil {
		return nil, fmt.Errorf("cubecosapi: request for %s: %w", path, err)
	}
	req.Header.Set("Node", c.hostname)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// The error from Do can name the URL but never a header, so the token
		// cannot reach a log this way. Wrapping keeps context.DeadlineExceeded
		// unwrappable-to, which asTimeout checks.
		return nil, fmt.Errorf("cubecosapi: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// maxBytes+1 so truncation is detectable rather than inferred from an
	// exactly-full buffer, which a response of precisely maxBytes would fake.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	truncated := len(body) > maxBytes
	if truncated {
		body = body[:maxBytes]
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cubecosapi: GET %s: %s%s", path, resp.Status, hint(resp.StatusCode, c.tokenPath))
	}
	if readErr != nil {
		return body, fmt.Errorf("cubecosapi: reading %s: %w", path, readErr)
	}
	if truncated {
		return body, fmt.Errorf("%w at %d bytes", toolplane.ErrOutputTruncated, maxBytes)
	}
	return body, nil
}

// hint turns the two status codes an operator can act on into advice.
//
// A 401 here is almost always a stale token rather than a wrong one: the file
// is rewritten when cube-cos-api starts, and an agent that read it once would
// hold the old value — which is why the token is read per request, and why the
// remaining way to see a 401 is worth naming. A 404 is the datacenter, because
// {dc} is the only part of a catalogue path this agent supplies.
func hint(status int, tokenPath string) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf(" (the node token at %s was not accepted; cube-cos-api rewrites it at startup)", tokenPath)
	case http.StatusNotFound:
		return " (check the datacenter in " + toolplane.CubeCOSFileName + "; it must match this cluster's name)"
	}
	return ""
}

// token reads the node token for this request.
//
// Per request rather than once at construction, because cube-cos-api rewrites
// the file every time it starts and the value changes whenever the Keycloak
// client secret it derives from is rotated. A client that cached it would keep
// working until the API restarted and then fail in a way that looked like a
// configuration error and was fixed by restarting the agent — the worst kind
// of bug to diagnose. The file is small and local; reading it costs nothing
// worth saving.
//
// Its mode is not checked. cube-cos-api writes it 0644 and owns that choice;
// refusing to read a file the platform deliberately publishes would disable
// this agent over a decision it cannot change. That the token is readable by
// any local account is cube-cos-api's exposure, not one this introduces.
func (c *Client) token() (string, error) {
	b, err := os.ReadFile(c.tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("cubecosapi: no node token at %s; cube-cos-api writes it at startup, so this node's api may not have run yet", c.tokenPath)
	}
	if err != nil {
		return "", fmt.Errorf("cubecosapi: read %s: %w", c.tokenPath, err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("cubecosapi: node token at %s is empty", c.tokenPath)
	}
	return token, nil
}
