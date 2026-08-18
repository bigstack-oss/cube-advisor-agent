package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Enrollment errors a caller should distinguish, because the operator's next
// action differs for each: get a fresh token, fix connectivity, or re-enroll.
var (
	ErrTokenRejected   = errors.New("identity: pairing token rejected")
	ErrAlreadyEnrolled = errors.New("identity: this node already has an identity")
)

// EnrollRequest is what the agent sends. A CSR and a cluster name — nothing
// else, and in particular no key material.
type EnrollRequest struct {
	ClusterID    string `json:"clusterId"`
	CSR          string `json:"csr"`
	Fingerprint  string `json:"fingerprint"` // so the operator can compare on both screens
	AgentVersion string `json:"agentVersion"`
}

// EnrollResponse is what the SaaS returns.
type EnrollResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
}

// Enroller exchanges a pairing token for a signed identity.
type Enroller struct {
	// BaseURL of the SaaS enrollment endpoint.
	BaseURL string
	// HTTPClient is overridable for tests and for sites behind an egress proxy.
	HTTPClient *http.Client
	// AgentVersion is reported so an operator can see what enrolled.
	AgentVersion string
}

const enrollTimeout = 30 * time.Second

// Enroll generates a key, requests a certificate for clusterID with the pairing
// token, and returns the resulting identity. It does not write anything to
// disk; the caller decides where an identity lives.
//
// The token authenticates this one request and is deliberately not stored: it
// is single-use, and an unused copy on disk is a credential nobody is watching.
func (e *Enroller) Enroll(ctx context.Context, clusterID, token string) (*Identity, error) {
	if token == "" {
		return nil, fmt.Errorf("identity: enrollment needs a pairing token")
	}
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	csr, err := CSR(key, clusterID)
	if err != nil {
		return nil, err
	}
	fp, err := Fingerprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(EnrollRequest{
		ClusterID:    clusterID,
		CSR:          string(csr),
		Fingerprint:  fp,
		AgentVersion: e.AgentVersion,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.BaseURL+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// The token travels in a header rather than the body so it does not end up
	// in a request log that records payloads.
	req.Header.Set("Authorization", "Bearer "+token)

	client := e.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: enrollTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity: enrollment service unreachable: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w: ask for a fresh pairing token", ErrTokenRejected)
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		return nil, fmt.Errorf("identity: enrollment failed (%s): %s",
			resp.Status, bytes.TrimSpace(msg))
	}

	var out EnrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("identity: unreadable enrollment response: %w", err)
	}
	if out.Certificate == "" {
		return nil, fmt.Errorf("identity: enrollment returned no certificate")
	}

	id := &Identity{
		ClusterID: clusterID,
		key:       key,
		certPEM:   []byte(out.Certificate),
		caPEM:     []byte(out.CA),
	}
	// A certificate that does not match the key we just made means something is
	// badly wrong upstream; better to fail here than at the first tunnel dial.
	if _, err := id.TLSConfig(""); err != nil {
		return nil, err
	}
	return id, nil
}

// EnrollAndSave is the operator-facing path: enroll, then persist to dir.
//
// It refuses when dir already holds an identity. Re-enrolling should be a
// deliberate act — running the command twice must not quietly invalidate the
// certificate the SaaS is currently accepting.
func (e *Enroller) EnrollAndSave(ctx context.Context, dir, clusterID, token string) (*Identity, error) {
	if Exists(dir) {
		return nil, fmt.Errorf("%w at %s; remove it first to re-enrol", ErrAlreadyEnrolled, dir)
	}
	id, err := e.Enroll(ctx, clusterID, token)
	if err != nil {
		return nil, err
	}
	if err := id.Save(dir); err != nil {
		return nil, err
	}
	return id, nil
}

// PublicKeyOf exposes a key's public half, for callers computing a fingerprint
// before enrolment.
func PublicKeyOf(k *ecdsa.PrivateKey) *ecdsa.PublicKey { return &k.PublicKey }
