package openstack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCloud is a Keystone and a nova on one listener, so a test can exercise
// the whole path — redeem a credential, read the catalog, post a server —
// without a cluster.
type fakeCloud struct {
	mu sync.Mutex

	tokenCalls  int
	serverCalls int

	lastToken string
	lastBody  []byte
	lastKey   string

	// knobs
	projectName string
	noCompute   bool
	expiresIn   time.Duration
	novaStatus  int
	novaBody    string

	srv *httptest.Server
}

func newFakeCloud(t *testing.T) *fakeCloud {
	t.Helper()
	f := &fakeCloud{projectName: "acme-prod", expiresIn: time.Hour, novaStatus: http.StatusAccepted}
	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.tokenCalls++
		n := f.tokenCalls
		f.mu.Unlock()

		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		catalog := []map[string]any{}
		if !f.noCompute {
			catalog = append(catalog, map[string]any{
				"type": "compute",
				"endpoints": []map[string]any{
					{"interface": "public", "url": f.srv.URL + "/compute-public"},
					{"interface": "internal", "url": f.srv.URL + "/compute/v2.1"},
				},
			})
		}
		w.Header().Set("X-Subject-Token", fmt.Sprintf("tok-%d", n))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": map[string]any{
				"expires_at": time.Now().Add(f.expiresIn),
				"project":    map[string]any{"name": f.projectName, "id": "p1"},
				"catalog":    catalog,
			},
		})
	})

	mux.HandleFunc("/compute/v2.1/servers", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.serverCalls++
		f.lastToken = r.Header.Get("X-Auth-Token")
		f.lastKey = r.Header.Get("Idempotency-Key")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		f.lastBody = buf
		f.mu.Unlock()

		w.WriteHeader(f.novaStatus)
		if f.novaBody != "" {
			_, _ = w.Write([]byte(f.novaBody))
			return
		}
		_, _ = w.Write([]byte(`{"server":{"id":"i-1"}}`))
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCloud) credential() Credential {
	return Credential{
		AuthURL: f.srv.URL + "/v3",
		ID:      "abc123",
		Secret:  testSecret,
		Project: "acme-prod",
	}
}

func (f *fakeCloud) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenCalls, f.serverCalls
}

func TestACreateReachesNovaWithATokenAndTheBodyItWasGiven(t *testing.T) {
	f := newFakeCloud(t)
	c, err := NewCompute(f.credential())
	if err != nil {
		t.Fatalf("NewCompute: %v", err)
	}

	body := []byte(`{"server":{"name":"web-03"}}`)
	out, err := c.Post(context.Background(), "/servers", body, "key-1", 1<<16)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if !strings.Contains(string(out), "i-1") {
		t.Errorf("output = %s", out)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastToken != "tok-1" {
		t.Errorf("nova saw token %q", f.lastToken)
	}
	if f.lastKey != "key-1" {
		t.Errorf("nova saw idempotency key %q", f.lastKey)
	}
	if string(f.lastBody) != string(body) {
		t.Errorf("nova saw body %s, want %s", f.lastBody, body)
	}
}

// The endpoint is the catalog's, not configuration's. An operator who moves
// nova changes nothing in the agent — which is why the allowlist writes only
// "/servers".
func TestTheComputeEndpointComesFromTheCatalogAndPrefersInternal(t *testing.T) {
	f := newFakeCloud(t)
	c, _ := NewCompute(f.credential())
	if _, err := c.Post(context.Background(), "/servers", []byte(`{}`), "", 1<<16); err != nil {
		t.Fatalf("Post: %v", err)
	}
	// The internal endpoint is /compute/v2.1; the public one is served by no
	// handler, so reaching it at all would 404 and fail the call above.
	if _, servers := f.counts(); servers != 1 {
		t.Errorf("nova was called %d times at the internal endpoint", servers)
	}
}

func TestNoComputeInTheCatalogIsALegibleRefusal(t *testing.T) {
	f := newFakeCloud(t)
	f.noCompute = true
	c, _ := NewCompute(f.credential())
	_, err := c.Post(context.Background(), "/servers", []byte(`{}`), "", 1<<16)
	if err == nil {
		t.Fatal("a catalog with no compute service was accepted")
	}
	if !strings.Contains(err.Error(), "compute") {
		t.Errorf("the error does not say what was missing: %v", err)
	}
}

// A token is fetched once and reused. Re-authenticating per call would be
// slow and would multiply the credential's exposure for nothing.
func TestATokenIsCachedAcrossCalls(t *testing.T) {
	f := newFakeCloud(t)
	c, _ := NewCompute(f.credential())
	for i := 0; i < 3; i++ {
		if _, err := c.Post(context.Background(), "/servers", []byte(`{}`), "", 1<<16); err != nil {
			t.Fatalf("Post %d: %v", i, err)
		}
	}
	tokens, servers := f.counts()
	if tokens != 1 {
		t.Errorf("authenticated %d times for 3 calls", tokens)
	}
	if servers != 3 {
		t.Errorf("nova saw %d calls, want 3", servers)
	}
}

// A token about to expire is replaced before it is used, so a create does not
// fail for a reason the model cannot interpret.
func TestATokenInsideTheRenewMarginIsReplaced(t *testing.T) {
	f := newFakeCloud(t)
	f.expiresIn = renewMargin / 2
	c, _ := NewCompute(f.credential())
	for i := 0; i < 2; i++ {
		if _, err := c.Post(context.Background(), "/servers", []byte(`{}`), "", 1<<16); err != nil {
			t.Fatalf("Post %d: %v", i, err)
		}
	}
	if tokens, _ := f.counts(); tokens != 2 {
		t.Errorf("authenticated %d times; a token inside the margin should be replaced", tokens)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastToken != "tok-2" {
		t.Errorf("nova saw %q; the renewed token should have been used", f.lastToken)
	}
}

// The operator's belief about which project this agent creates in must match
// the credential's actual scope, or the safe reading is to refuse.
func TestACredentialScopedElsewhereIsRefused(t *testing.T) {
	f := newFakeCloud(t)
	f.projectName = "someone-elses-project"
	c, _ := NewCompute(f.credential())
	_, err := c.Post(context.Background(), "/servers", []byte(`{}`), "", 1<<16)
	if err == nil {
		t.Fatal("a credential scoped to another project was accepted")
	}
	if !strings.Contains(err.Error(), "someone-elses-project") || !strings.Contains(err.Error(), "acme-prod") {
		t.Errorf("the error does not name both projects: %v", err)
	}
	if _, servers := f.counts(); servers != 0 {
		t.Errorf("nova was called %d times despite the scope mismatch", servers)
	}
}

// nova's own error is the diagnosis an operator needs — "flavor not found" is
// the whole answer — so it is passed through rather than flattened.
func TestNovasRefusalIsPassedThroughLegibly(t *testing.T) {
	f := newFakeCloud(t)
	f.novaStatus = http.StatusBadRequest
	f.novaBody = `{"badRequest":{"message":"Flavor m1.enormous could not be found"}}`
	c, _ := NewCompute(f.credential())
	_, err := c.Post(context.Background(), "/servers", []byte(`{}`), "", 1<<16)
	if err == nil {
		t.Fatal("a 400 was reported as success")
	}
	if !strings.Contains(err.Error(), "m1.enormous") {
		t.Errorf("nova's diagnosis was lost: %v", err)
	}
}

// Keystone refusing must not echo the request back, because the request holds
// the secret.
func TestAKeystoneRefusalNeverQuotesTheSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		w.WriteHeader(http.StatusUnauthorized)
		// A hostile or merely careless Keystone echoing the request.
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c, _ := NewCompute(Credential{
		AuthURL: srv.URL + "/v3", ID: "abc123", Secret: testSecret, Project: "acme-prod",
	})
	_, err := c.Post(context.Background(), "/servers", []byte(`{}`), "", 1<<16)
	if err == nil {
		t.Fatal("a 401 was accepted")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("the error carries the secret: %v", err)
	}
}
