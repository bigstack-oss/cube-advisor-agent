package broker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/openstack"
)

type fakeOS struct {
	base        string
	mu          sync.Mutex
	invalidated int
}

func (f *fakeOS) Endpoint(_ context.Context, service string) (string, string, error) {
	switch service {
	case "compute":
		return f.base + "/v2.1", "tok", nil
	case "identity":
		return f.base + "/v3/", "tok", nil
	case "image":
		return f.base, "tok", nil
	}
	return "", "", openstack.ErrUnknownService
}

func (f *fakeOS) Invalidate() { f.mu.Lock(); f.invalidated++; f.mu.Unlock() }

func (f *fakeOS) HTTP() *http.Client { return http.DefaultClient }

// startOS serves os.sock against a fake OpenStack that records what reached it.
func startOS(t *testing.T, backend http.HandlerFunc) (*memAudit, *http.Client, *[]string, *fakeOS, string) {
	t.Helper()
	var seen []string
	var mu sync.Mutex
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" token="+r.Header.Get("X-Auth-Token")+" mv="+r.Header.Get("OpenStack-API-Version"))
		mu.Unlock()
		if backend != nil {
			backend(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(api.Close)
	f := &fakeOS{base: api.URL}
	_, audit, dir := start(t, http.NotFoundHandler(), func(s *Server) { s.OpenStack = f })
	return audit, unixClient(filepath.Join(dir, "os.sock")), &seen, f, dir
}

func osCall(t *testing.T, c *http.Client, method, service, path string) (int, string) {
	t.Helper()
	u := "http://broker/get?" + url.Values{"service": {service}, "path": {path}}.Encode()
	req, _ := http.NewRequest(method, u, nil)
	req.Header.Set("OpenStack-API-Version", "compute 2.90")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestOSForwardsGETsUnderTheEndpoint(t *testing.T) {
	audit, c, seen, _, _ := startOS(t, nil)
	for _, p := range []string{"/servers/detail?all_tenants=1&status=ERROR", "/v2.1/servers/detail?status=ERROR&all_tenants=1"} {
		if code, out := osCall(t, c, http.MethodGet, "compute", p); code != 200 || out != `{"ok":true}` {
			t.Fatalf("%s: %d %s", p, code, out)
		}
	}
	if code, _ := osCall(t, c, http.MethodGet, "identity", "/v3/projects"); code != 200 {
		t.Fatalf("identity projects: %d", code)
	}
	want := []string{
		"GET /v2.1/servers/detail?all_tenants=1&status=ERROR token=tok mv=",
		"GET /v2.1/servers/detail?all_tenants=1&status=ERROR token=tok mv=",
		"GET /v3/projects token=tok mv=",
	}
	if strings.Join(*seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("backend saw\n%s", strings.Join(*seen, "\n"))
	}
	if a := audit.calls[0]; a.Tool != "broker:os" || !a.Allowed || a.Args["service"] != "compute" {
		t.Errorf("audit = %+v", a)
	}
}

func TestOSRefusesNonGET(t *testing.T) {
	audit, c, seen, _, _ := startOS(t, nil)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		if code, _ := osCall(t, c, m, "compute", "/servers/detail"); code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", m, code)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("refused calls reached OpenStack: %v", *seen)
	}
	for _, a := range audit.calls {
		if a.Allowed {
			t.Errorf("audit allowed %+v", a)
		}
	}
}

// QA row 2 and the tricks around the deny list.
func TestOSRefusesSecretPathsAndTricks(t *testing.T) {
	audit, c, seen, _, _ := startOS(t, nil)
	denied := []struct{ service, path string }{
		{"identity", "/v3/credentials"},
		{"identity", "/credentials"},
		{"identity", "/v3/CREDENTIALS"},
		{"identity", "/v3/Credentials/"},
		{"identity", "/v3/credentials?user_id=x"},
		{"identity", "/v3/users/u1/application_credentials"},
		{"identity", "/v3/users/u1/credentials/OS-EC2"},
		{"identity", "/v3/OS-OAUTH1/access_tokens"},
		{"identity", "/v3/projects/../credentials"},
		{"identity", "/v3/projects/%2e%2e/credentials"},
		{"identity", "/v3/projects%2F..%2Fcredentials"},
		{"identity", "/v3/cred%65ntials"},
		{"identity", "/v3//credentials"},
		{"identity", "/v3/./credentials"},
		{"identity", "/v3/projects/./../credentials"},
		{"identity", `/v3/projects\..\credentials`},
		{"identity", "/v3/projects;/credentials"},
		{"identity", "/v3/projects#/../credentials"},
		{"identity", "v3/credentials"},
		{"identity", ""},
		{"compute", "/os-keypairs"},
		{"compute", "/OS-KEYPAIRS"},
		{"compute", "/v2.1/os-keypairs/k1"},
		{"compute", "/servers/s1/os-server-password"},
		{"compute", "/os-console-auth-tokens/t1"},
		{"compute", "/servers/.../os-keypairs"},
		{"image", "/v2/images/i1/file"},
		{"key-manager", "/v1/secrets"},
		{"key-manager", "/v1/containers"},
		{"key-manager", "/v1/secrets/s1/payload"},
		{"object-store", "/v1/AUTH_x/c/o"},
		{"orchestration", "/v1/p/stacks/s/i/environment"},
		{"share", "/v2/share-access-rules"},
		{"network", "/v2.0/vpn/ipsec-site-connections"},
		{"dns", "/v2/tsigkeys"},
	}
	for _, d := range denied {
		if code, out := osCall(t, c, http.MethodGet, d.service, d.path); code == 200 {
			t.Errorf("%s %q forwarded: %s", d.service, d.path, out)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("denied calls reached OpenStack:\n%s", strings.Join(*seen, "\n"))
	}
	if n := len(audit.calls); n != len(denied) {
		t.Fatalf("%d audit records for %d refusals", n, len(denied))
	}
	// A query cannot move the path.
	if code, _ := osCall(t, c, http.MethodGet, "compute", "/servers?x=/../os-keypairs"); code != 200 ||
		(*seen)[0] != "GET /v2.1/servers?x=%2F..%2Fos-keypairs token=tok mv=" {
		t.Fatalf("query: %d %v", code, *seen)
	}
}

func TestOSValidatesTheServiceName(t *testing.T) {
	_, c, seen, _, _ := startOS(t, nil)
	for _, svc := range []string{"", "Compute", "compute/../identity", "../compute", "comp ute", "compute?x=1", "-compute", "nosuch",
		strings.Repeat("a", 41)} {
		if code, _ := osCall(t, c, http.MethodGet, svc, "/servers"); code == 200 {
			t.Errorf("service %q forwarded", svc)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("calls reached OpenStack: %v", *seen)
	}
	if code, _ := osCall(t, c, http.MethodGet, "nosuch", "/x"); code != http.StatusNotFound {
		t.Errorf("unknown service: %d", code)
	}
}

func TestOSOnlyServesGet(t *testing.T) {
	_, c, _, _, _ := startOS(t, nil)
	resp, err := c.Get("http://broker/servers/detail")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("other path: %d", resp.StatusCode)
	}
}

func TestOSRetriesOnceAfter401(t *testing.T) {
	calls := 0
	_, c, seen, f, _ := startOS(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "{}")
	})
	if code, _ := osCall(t, c, http.MethodGet, "compute", "/servers"); code != 200 || len(*seen) != 2 || f.invalidated != 1 {
		t.Fatalf("code %d, seen %v, invalidated %d", code, *seen, f.invalidated)
	}
}

func TestOSWithoutCredentialRefuses(t *testing.T) {
	_, _, dir := start(t, http.NotFoundHandler())
	code, _ := osCall(t, unixClient(filepath.Join(dir, "os.sock")), http.MethodGet, "compute", "/servers")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", code)
	}
}

func TestOSClientCommand(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	_, _, seen, _, dir := startOS(t, nil)
	bin := filepath.Join(dir, "bin", "os-ro")
	out, err := exec.Command(bin, "GET", "compute", "/servers/detail?all_tenants=1&status=ERROR").CombinedOutput()
	if err != nil || string(out) != `{"ok":true}` {
		t.Fatalf("os-ro GET: %q %v", out, err)
	}
	out, _ = exec.Command(bin, "DELETE", "compute", "/servers/s1").CombinedOutput()
	if !strings.Contains(string(out), "only GET") {
		t.Fatalf("os-ro DELETE: %q", out)
	}
	out, _ = exec.Command(bin, "GET", "identity", "/v3/credentials").CombinedOutput()
	if !strings.Contains(string(out), "not served") {
		t.Fatalf("os-ro credentials: %q", out)
	}
	var ee *exec.ExitError
	if _, err := exec.Command(bin, "GET", "compute").CombinedOutput(); !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("usage: %v", err)
	}
	if len(*seen) != 1 || !strings.HasPrefix((*seen)[0], "GET /v2.1/servers/detail?all_tenants=1&status=ERROR ") {
		t.Fatalf("backend saw %v", *seen)
	}
}
