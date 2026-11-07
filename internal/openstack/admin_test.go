package openstack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeOpenrc(t *testing.T, authURL string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "admin-openrc.sh")
	body := "export OS_AUTH_TYPE=password\nexport OS_USERNAME=admin_cli\nexport OS_PASSWORD='s3cret'\n" +
		"export OS_PROJECT_NAME=\"admin\"\nexport OS_USER_DOMAIN_NAME=default\nexport OS_PROJECT_DOMAIN_NAME=default\n" +
		"export OS_AUTH_URL=" + authURL + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadOpenrc(t *testing.T) {
	o, err := ReadOpenrc(writeOpenrc(t, "http://10.0.0.1:5000/v3"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Username != "admin_cli" || o.Password != "s3cret" || o.Project != "admin" || o.UserDomain != "default" {
		t.Fatalf("parsed %+v", o)
	}
	if s := fmt.Sprintf("%v %+v %#v", o, o, o); strings.Contains(s, "s3cret") {
		t.Fatalf("password printed: %s", s)
	}
	p := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(p, []byte("export OS_USERNAME=a\n"), 0o600)
	if _, err := ReadOpenrc(p); err == nil {
		t.Fatal("incomplete openrc accepted")
	}
}

func TestAdminAuthenticatesWithPasswordAndCachesTheCatalogue(t *testing.T) {
	auths := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v3/auth/tokens" {
			http.NotFound(w, r)
			return
		}
		auths++
		var body struct {
			Auth struct {
				Identity struct {
					Methods  []string `json:"methods"`
					Password struct {
						User struct {
							Name     string `json:"name"`
							Password string `json:"password"`
						} `json:"user"`
					} `json:"password"`
				} `json:"identity"`
			} `json:"auth"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Auth.Identity.Methods[0] != "password" || body.Auth.Identity.Password.User.Password != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-Subject-Token", fmt.Sprintf("tok%d", auths))
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"token":{"expires_at":%q,"catalog":[
			{"type":"compute","endpoints":[{"interface":"public","url":"http://pub/v2.1"},{"interface":"internal","url":"http://int/v2.1"}]},
			{"type":"image","endpoints":[{"interface":"public","url":"http://img"}]}]}}`, time.Now().Add(time.Hour).Format(time.RFC3339))
	}))
	defer srv.Close()
	a := NewAdmin(writeOpenrc(t, srv.URL+"/v3"))
	ctx := context.Background()
	ep, tok, err := a.Endpoint(ctx, "compute")
	if err != nil || ep != "http://int/v2.1" || tok != "tok1" {
		t.Fatalf("compute: %q %q %v", ep, tok, err)
	}
	if ep, _, _ := a.Endpoint(ctx, "image"); ep != "http://img" || auths != 1 {
		t.Fatalf("image: %q after %d auths", ep, auths)
	}
	if _, _, err := a.Endpoint(ctx, "key-manager"); !errors.Is(err, ErrUnknownService) {
		t.Fatalf("unknown service: %v", err)
	}
	a.Invalidate()
	if _, tok, _ := a.Endpoint(ctx, "compute"); tok != "tok2" {
		t.Fatalf("after invalidate: %q", tok)
	}
}
