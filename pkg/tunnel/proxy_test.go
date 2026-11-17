package tunnel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
)

// advisorName is the server name the env tests dial. Not "localhost" or an IP:
// HTTPS_PROXY is never applied to loopback.
const advisorName = "advisor.test"

// mtlsEcho is a wss echo server that, like the Advisor, refuses a client
// without a certificate from its CA. client is a TLS config that passes.
func mtlsEcho(t *testing.T) (srv *httptest.Server, client *tls.Config) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test enrolment CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "node"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{usage},
			DNSNames:    []string{advisorName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := tunnel.AcceptWS(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{issue(2, x509.ExtKeyUsageServerAuth)},
		ClientCAs:    pool, ClientAuth: tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{issue(3, x509.ExtKeyUsageClientAuth)},
		MinVersion: tls.VersionTLS12,
	}
}

// connectProxy is a pass-through CONNECT proxy that records each target and
// sends advisorName to the loopback.
type connectProxy struct {
	*httptest.Server
	mu      sync.Mutex
	targets []string
}

func newConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	p := &connectProxy{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		p.mu.Lock()
		p.targets = append(p.targets, r.Host)
		p.mu.Unlock()
		host, port, _ := net.SplitHostPort(r.Host)
		if host == advisorName {
			host = "127.0.0.1"
		}
		up, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		down, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = down.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, down); up.Close() }()
		_, _ = io.Copy(down, up)
		down.Close()
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *connectProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *connectProxy) url(t *testing.T) *url.URL {
	u, err := url.Parse(p.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// echoOnce dials url with client and round-trips one message.
func echoOnce(ctx context.Context, url string, client *http.Client) error {
	conn, err := tunnel.DialWS(ctx, url, nil, client)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func wssURL(srv *httptest.Server) string {
	return "wss" + strings.TrimPrefix(srv.URL, "https") + tunnel.WSPath
}

func ctx5s(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The mTLS tunnel crosses a CONNECT proxy: the proxy sees the CONNECT, the
// TLS and the client certificate pass through it untouched.
func TestDialWSThroughConnectProxy(t *testing.T) {
	srv, cfg := mtlsEcho(t)
	proxy := newConnectProxy(t)
	client := tunnel.NewTLSClientVia(cfg, http.ProxyURL(proxy.url(t)))
	if err := echoOnce(ctx5s(t), wssURL(srv), client); err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	want := strings.TrimPrefix(srv.URL, "https://")
	if got := proxy.seen(); len(got) != 1 || got[0] != want {
		t.Errorf("proxy CONNECTs = %v, want [%s]", got, want)
	}
}

// No proxy configured is today's behaviour: a direct dial.
func TestDialWSDirectWithoutProxy(t *testing.T) {
	srv, cfg := mtlsEcho(t)
	proxy := newConnectProxy(t)
	if err := echoOnce(ctx5s(t), wssURL(srv), tunnel.NewTLSClient(cfg)); err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	if got := proxy.seen(); len(got) != 0 {
		t.Errorf("proxy CONNECTs = %v, want none", got)
	}
}

// A configured proxy that is down fails the dial rather than going direct.
func TestDialWSDoesNotBypassADeadProxy(t *testing.T) {
	srv, cfg := mtlsEcho(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &url.URL{Scheme: "http", Host: l.Addr().String()}
	l.Close()
	if err := echoOnce(ctx5s(t), wssURL(srv), tunnel.NewTLSClientVia(cfg, http.ProxyURL(dead))); err == nil {
		t.Fatal("dial succeeded with the proxy down: it went direct")
	}
}

// http.ProxyFromEnvironment reads the environment once per process, so each
// case runs in a child with its own.
func TestDialWSFollowsProxyEnvironment(t *testing.T) {
	for _, mode := range []string{"proxied", "no_proxy"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestEnvProxyChild$", "-test.v")
			cmd.Env = append(os.Environ(), "TUNNEL_ENV_CHILD="+mode)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("child %s: %v\n%s", mode, err, out)
			}
		})
	}
}

func TestEnvProxyChild(t *testing.T) {
	mode := os.Getenv("TUNNEL_ENV_CHILD")
	if mode == "" {
		t.Skip("run by TestDialWSFollowsProxyEnvironment")
	}
	srv, cfg := mtlsEcho(t)
	proxy := newConnectProxy(t)
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		os.Unsetenv(k)
	}
	os.Setenv("HTTPS_PROXY", proxy.URL)
	if mode == "no_proxy" {
		os.Setenv("NO_PROXY", advisorName)
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	target := net.JoinHostPort(advisorName, port)
	err := echoOnce(ctx5s(t), "wss://"+target+tunnel.WSPath, tunnel.NewTLSClientVia(cfg, http.ProxyFromEnvironment))
	got := proxy.seen()
	switch mode {
	case "proxied":
		if err != nil {
			t.Fatalf("dial via HTTPS_PROXY: %v", err)
		}
		if len(got) != 1 || got[0] != target {
			t.Errorf("proxy CONNECTs = %v, want [%s]", got, target)
		}
	case "no_proxy":
		// advisor.test does not resolve, so a direct dial fails: what matters
		// is that the proxy was not asked.
		if len(got) != 0 {
			t.Errorf("proxy CONNECTs = %v with NO_PROXY=%s, want none", got, advisorName)
		}
		if err == nil {
			t.Errorf("dial succeeded; want a direct dial to the unresolvable %s", advisorName)
		}
	}
}
