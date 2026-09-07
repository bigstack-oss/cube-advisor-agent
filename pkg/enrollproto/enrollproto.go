// Package enrollproto is the wire contract for enrollment: the request an agent
// sends to exchange a pairing token for an identity, and the response it gets.
//
// It lives here, in the public repository, for the same reason pkg/tunnelproto
// does. Both sides must agree on these shapes, and a contract defined twice is
// a contract neither side owns — the SaaS imports this rather than restating it.
//
// The client that speaks this protocol stays agent-side and unexported; only
// the shapes are shared.
package enrollproto

// Path is the endpoint an agent posts to.
const Path = "/api/v1/enroll"

// Request is what the agent sends.
//
// Note what is absent: any private key. The agent generates its keypair on the
// cluster and sends only a certificate signing request, so the service never
// holds material that would let it impersonate the cluster.
type Request struct {
	ClusterID string `json:"clusterId"`

	// CSR is PEM, carrying the public key and the node's and cluster's names
	// (CommonName and OrganizationalUnit, respectively).
	CSR string `json:"csr"`

	// Fingerprint is the agent's own derivation from its public key. The
	// service recomputes it from the CSR and refuses a mismatch: an operator
	// compares this string on two screens, so the two sides must agree on it
	// before anyone is asked to trust it.
	Fingerprint string `json:"fingerprint"`

	AgentVersion string `json:"agentVersion"`
}

// Response is what the service returns on success.
type Response struct {
	// Certificate is the signed per-cluster certificate, PEM.
	Certificate string `json:"certificate"`

	// CA is the enrollment authority, PEM. The agent pins it as the only root
	// it trusts for the tunnel, so it talks to the service that enrolled it
	// rather than anything holding a publicly-issued certificate.
	CA string `json:"ca"`
}
