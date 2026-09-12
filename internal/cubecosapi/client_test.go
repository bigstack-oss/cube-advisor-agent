package cubecosapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

// clientFor builds a client against srv, with its token read from a temp file
// rather than /var/run, which a test cannot write.
func clientFor(t *testing.T, srv *httptest.Server, token string) *Client {
	t.Helper()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	path := filepath.Join(t.TempDir(), "node_token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.tokenPath = path
	return c
}

// The node-to-node path is what cube-cos-api checks first and the only one an
// on-node daemon can satisfy: Node names this host, Authorization carries the
// token that host's api wrote. Verified against a real cube-cos-api on the 1cc
// R630, where the same two headers turn a 401 into a 200.
func TestTheNodeTokenAndHostnameAreSent(t *testing.T) {
	var gotNode, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNode, gotAuth = r.Header.Get("Node"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"code":200}`))
	}))
	defer srv.Close()

	c := clientFor(t, srv, "a-node-token")
	if _, err := c.Get(context.Background(), "/api/v1/datacenters/dc/healths", 4096); err != nil {
		t.Fatalf("Get: %v", err)
	}

	host, _ := os.Hostname()
	if gotNode != host {
		t.Errorf("Node = %q, want this host %q; cube-cos-api hashes whatever this header says", gotNode, host)
	}
	if gotAuth != "Bearer a-node-token" {
		t.Errorf("Authorization = %q, want the token from the file", gotAuth)
	}
}

// cube-cos-api rewrites the token file whenever it starts, so a client that
// read it once would fail after an api restart in a way that looks like
// misconfiguration and is cured by restarting the agent.
func TestTheTokenIsReadForEveryRequest(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	c := clientFor(t, srv, "first")
	if _, err := c.Get(context.Background(), "/a", 4096); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.tokenPath, []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "/a", 4096); err != nil {
		t.Fatal(err)
	}

	if len(seen) != 2 || seen[0] != "Bearer first" || seen[1] != "Bearer second" {
		t.Errorf("Authorization headers = %v; a rotated token must be picked up without restarting", seen)
	}
}

// The truncation contract toolplane.fetch relies on: the getter returns the
// capped body and ErrOutputTruncated, and the caller writes the marker. One
// place decides what a cut looks like, and tool-0010 measures whether the model
// reports it.
func TestAnOverLongResponseIsCappedAndSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 500)))
	}))
	defer srv.Close()

	body, err := clientFor(t, srv, "t").Get(context.Background(), "/a", 100)
	if !errors.Is(err, toolplane.ErrOutputTruncated) {
		t.Fatalf("err = %v, want ErrOutputTruncated so fetch adds the marker", err)
	}
	if len(body) != 100 {
		t.Errorf("body = %d bytes, want the cap of 100", len(body))
	}
}

// A response of exactly maxBytes is not truncated. Reading maxBytes+1 is what
// distinguishes the two; a client reading maxBytes would report every
// exactly-full response as cut.
func TestAResponseOfExactlyTheCapIsNotTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()

	body, err := clientFor(t, srv, "t").Get(context.Background(), "/a", 100)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(body) != 100 {
		t.Errorf("body = %d bytes, want 100", len(body))
	}
}

// A failing status names the status and, for the two an operator can act on,
// what to check — but never the token, and never the request that carried it.
func TestAFailedStatusNeverCarriesTheToken(t *testing.T) {
	const token = "a-secret-node-token"
	for _, tc := range []struct {
		status int
		want   string
	}{
		{http.StatusUnauthorized, "node token at"},
		{http.StatusNotFound, toolplane.CubeCOSFileName},
		{http.StatusInternalServerError, "500"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// An api that echoes the request is the hazard: the request holds
			// the token, so the client must not repeat the body either.
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("Authorization: Bearer " + token))
		}))
		_, err := clientFor(t, srv, token).Get(context.Background(), "/a", 4096)
		srv.Close()

		if err == nil {
			t.Fatalf("status %d returned no error", tc.status)
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("status %d: the error carries the node token: %v", tc.status, err)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status %d: error %q does not mention %q", tc.status, err, tc.want)
		}
	}
}

// The token never reaches a log through the client either, under any of the
// verbs that print a struct. Credential.String makes the same promise for the
// same reason.
func TestAClientNeverPrintsItsBaseURL(t *testing.T) {
	c, err := New("http://10.32.1.200:8082")
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		got := fmt.Sprintf(format, c)
		if strings.Contains(got, "10.32.1.200") {
			t.Errorf("%s printed the management address: %s", format, got)
		}
	}
	if got := fmt.Sprintf("%v", []*Client{c}); strings.Contains(got, "10.32.1.200") {
		t.Errorf("a client inside a slice printed the management address: %s", got)
	}
}

// A base url this client cannot speak is refused at construction, where an
// operator sees it in a startup line, rather than on the first read.
func TestABaseURLMustBeHTTP(t *testing.T) {
	for _, bad := range []string{"ftp://h/x", "unix:///var/run/s", "10.32.1.200:8082", ""} {
		if _, err := New(bad); err == nil {
			t.Errorf("New(%q) was accepted", bad)
		}
	}
}

// A path is resolved against the base, never allowed to replace it: a caller
// that could supply an absolute url would choose where the node token goes,
// which is the escalation the config file's mode check exists to prevent.
func TestAPathCannotRedirectTheRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := clientFor(t, srv, "t")
	for _, bad := range []string{"http://elsewhere.example/x", "//elsewhere.example/x"} {
		if _, err := c.Get(context.Background(), bad, 4096); err == nil {
			t.Errorf("Get(%q) was accepted; it would send the node token elsewhere", bad)
		}
	}
}

// An agent whose node has never run cube-cos-api says so, rather than failing
// with a bare open error an operator has to interpret.
func TestAMissingTokenFileSaysWhereItComesFrom(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := clientFor(t, srv, "t")
	c.tokenPath = filepath.Join(t.TempDir(), "absent")
	_, err := c.Get(context.Background(), "/a", 4096)
	if err == nil {
		t.Fatal("a missing token file did not fail")
	}
	if !strings.Contains(err.Error(), "absent") || !strings.Contains(err.Error(), "cube-cos-api writes it") {
		t.Errorf("error %q does not say which file is missing or who writes it", err)
	}
}
