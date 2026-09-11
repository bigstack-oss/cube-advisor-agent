package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// ErrNotAllowed is returned for a target this node does not expose.
var ErrNotAllowed = errors.New("console: target is not in this node's web allowlist")

// WebAllowlist maps a symbolic target name to one host:port.
//
// One host per name, not a set: the protocol carries a name and nothing else,
// so a name that meant several addresses could not say which one it wanted.
type WebAllowlist map[string]string

// LoadWebAllowlist reads the allowlist. A missing file is an empty allowlist:
// a node that exposes no web target still serves SSH.
//
// JSON, not YAML, because the agent runs on customer nodes and does not take a
// dependency to read four lines of configuration.
func LoadWebAllowlist(path string) (WebAllowlist, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return WebAllowlist{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("console: read web allowlist: %w", err)
	}
	var a WebAllowlist
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("console: parse web allowlist: %w", err)
	}
	for name, hostport := range a {
		if _, _, err := net.SplitHostPort(hostport); err != nil {
			return nil, fmt.Errorf("console: web target %q: %w", name, err)
		}
	}
	return a, nil
}

// Resolve maps a name to its address, or refuses.
func (a WebAllowlist) Resolve(name string) (string, error) {
	hostport, ok := a[name]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrNotAllowed, name)
	}
	return hostport, nil
}

// WebHandler serves web channels for one node.
type WebHandler struct {
	// Allow is the only source of addresses. Empty refuses everything.
	Allow WebAllowlist

	// Dial opens the upstream connection; nil uses a real TCP dialler.
	Dial Dialer
}

// Serve pipes rw to the allowlisted address for name.
//
// Bytes only: the agent parses no HTTP, so there is no request it can be
// tricked into rewriting.
func (h *WebHandler) Serve(ctx context.Context, name string, rw io.ReadWriter) error {
	hostport, err := h.Allow.Resolve(name)
	if err != nil {
		return err
	}
	dial := h.Dial
	if dial == nil {
		dial = defaultDialer
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := dial(dialCtx, hostport)
	if err != nil {
		return fmt.Errorf("console: dial web target %q: %w", name, err)
	}
	defer conn.Close()
	return pipe(ctx, rw, conn)
}
