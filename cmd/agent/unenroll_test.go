package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/enrollproto"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// fakeAdvisor is an enrolment endpoint and an mTLS tunnel listener sharing
// one CA, as the Advisor's are.
type fakeAdvisor struct {
	enrollURL  string
	tunnelAddr string
	// hellos and kills are what the tunnel side received.
	hellos chan tunnelproto.Hello
	kills  chan tunnelproto.KillSwitch
	// refuse makes the tunnel refuse every Hello, as for a revoked identity.
	refuse bool
}

func newFakeAdvisor(t *testing.T) *fakeAdvisor {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	f := &fakeAdvisor{hellos: make(chan tunnelproto.Hello, 4), kills: make(chan tunnelproto.KillSwitch, 4)}

	enroll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req enrollproto.Request
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		blk, _ := pem.Decode([]byte(req.CSR))
		if blk == nil {
			http.Error(w, "no CSR", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil {
			http.Error(w, "bad CSR", http.StatusBadRequest)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{
				CommonName:         csr.Subject.CommonName,
				OrganizationalUnit: csr.Subject.OrganizationalUnit,
			},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(enrollproto.Response{
			Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CA:          string(caPEM),
		})
	}))
	t.Cleanup(enroll.Close)
	f.enrollURL = enroll.URL

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "advisor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	tun := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tunnel.WSPath {
			http.NotFound(w, r)
			return
		}
		conn, err := tunnel.AcceptWS(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		sess, err := tunnel.Accept(ctx, conn, func(h tunnelproto.Hello) tunnelproto.HelloAck {
			f.hellos <- h
			if f.refuse {
				return tunnelproto.HelloAck{Reason: "this node's identity was revoked"}
			}
			return tunnelproto.HelloAck{Accepted: true, ProtocolVersion: tunnelproto.Version}
		})
		if err != nil {
			return
		}
		defer sess.Close()
		// What the Advisor's side calls to receive the message.
		if k, err := sess.AwaitKillSwitch(); err == nil {
			f.kills <- k
		}
	}))
	tun.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
		ClientCAs:    pool, ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tun.StartTLS()
	t.Cleanup(tun.Close)
	f.tunnelAddr = tun.Listener.Addr().String()
	return f
}

// enrolledDir enrols a node against f and returns its identity directory.
func (f *fakeAdvisor) enrolledDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	code, _, errOut := dispatchCaptured(t, "enroll", "-server", f.enrollURL, "-cluster", "acme-prod-01",
		"-node", "sky141", "-dir", dir, "-token", "t", "-tunnel", f.tunnelAddr)
	if code != exitOK {
		t.Fatalf("enroll exit = %d: %s", code, errOut)
	}
	return dir
}

func listing(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		names = append(names, e.Name()+"="+string(b))
	}
	sort.Strings(names)
	return strings.Join(names, "\n")
}

func TestUnenrollTellsTheAdvisorTheCustomerCutTheClusterOff(t *testing.T) {
	f := newFakeAdvisor(t)
	dir := f.enrolledDir(t)
	before := listing(t, dir)

	code, out, errOut := dispatchCaptured(t, "unenroll", "-dir", dir)
	if code != exitOK {
		t.Fatalf("unenroll exit = %d, want %d: %s", code, exitOK, errOut)
	}
	select {
	case h := <-f.hellos:
		if h.ClusterID != "acme-prod-01" {
			t.Errorf("hello cluster = %q, want the enrolled cluster", h.ClusterID)
		}
	default:
		t.Fatal("the Advisor saw no hello")
	}
	select {
	case k := <-f.kills:
		if k.Reason != defaultUnenrollReason {
			t.Errorf("kill switch reason = %q, want %q", k.Reason, defaultUnenrollReason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the Advisor never received the kill switch")
	}
	if !strings.Contains(out, "told the Advisor") {
		t.Errorf("stdout = %q, want it to say the Advisor was told", out)
	}
	// CubeCOS deletes the identity; this command deletes nothing.
	if after := listing(t, dir); after != before {
		t.Errorf("unenroll changed the identity directory:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestUnenrollCarriesTheReasonItIsGiven(t *testing.T) {
	f := newFakeAdvisor(t)
	dir := f.enrolledDir(t)
	if code, _, errOut := dispatchCaptured(t, "unenroll", "-dir", dir, "-reason", "advisor disabled from the CLI"); code != exitOK {
		t.Fatalf("unenroll exit = %d: %s", code, errOut)
	}
	select {
	case k := <-f.kills:
		if k.Reason != "advisor disabled from the CLI" {
			t.Errorf("reason = %q", k.Reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the Advisor never received the kill switch")
	}
}

// notTold asserts the distinct exit code and the one clear stderr line.
func notTold(t *testing.T, code int, errOut string) {
	t.Helper()
	if code != exitNotTold {
		t.Fatalf("unenroll exit = %d, want %d: %s", code, exitNotTold, errOut)
	}
	if n := strings.Count(errOut, "\n"); n != 1 {
		t.Errorf("stderr has %d lines, want one: %q", n, errOut)
	}
	if !strings.Contains(errOut, "the Advisor could not be told") {
		t.Errorf("stderr = %q, want it to say the Advisor could not be told", errOut)
	}
}

func TestUnenrollSaysSoWhenTheAdvisorIsUnreachable(t *testing.T) {
	f := newFakeAdvisor(t)
	dir := f.enrolledDir(t)
	// A port nothing listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	code, _, errOut := dispatchCaptured(t, "unenroll", "-dir", dir, "-server", dead, "-timeout", "3s")
	notTold(t, code, errOut)
}

func TestUnenrollSaysSoWhenThereIsNoIdentity(t *testing.T) {
	code, _, errOut := dispatchCaptured(t, "unenroll", "-dir", t.TempDir())
	notTold(t, code, errOut)

	// An address but no key: still one line, same code.
	code, _, errOut = dispatchCaptured(t, "unenroll", "-dir", t.TempDir(), "-server", "127.0.0.1:1")
	notTold(t, code, errOut)
}

func TestUnenrollSaysSoWhenTheIdentityIsRevoked(t *testing.T) {
	f := newFakeAdvisor(t)
	dir := f.enrolledDir(t)
	f.refuse = true

	code, _, errOut := dispatchCaptured(t, "unenroll", "-dir", dir)
	notTold(t, code, errOut)
	if !strings.Contains(errOut, "revoked") {
		t.Errorf("stderr = %q, want the Advisor's reason", errOut)
	}
}

// An Advisor that accepts the connection and then says nothing must not hold
// the caller past -timeout.
func TestUnenrollGivesUpAtItsTimeout(t *testing.T) {
	f := newFakeAdvisor(t)
	dir := f.enrolledDir(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // held open, never answered
		}
	}()

	start := time.Now()
	code, _, errOut := dispatchCaptured(t, "unenroll", "-dir", dir, "-server", ln.Addr().String(), "-timeout", "300ms")
	notTold(t, code, errOut)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("unenroll took %s with -timeout 300ms", d)
	}
}

// The proxy file decides the route, as for run: a dead proxy is not bypassed.
func TestUnenrollDialsThroughTheProxyFile(t *testing.T) {
	f := newFakeAdvisor(t)
	dir := f.enrolledDir(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	writeProxy(t, dir, "http://"+dead)

	code, _, errOut := dispatchCaptured(t, "unenroll", "-dir", dir, "-timeout", "3s")
	notTold(t, code, errOut)
	select {
	case <-f.hellos:
		t.Error("unenroll reached the Advisor directly, around the configured proxy")
	default:
	}
}

func TestUnenrollRejectsANonPositiveTimeout(t *testing.T) {
	if code, _, _ := dispatchCaptured(t, "unenroll", "-timeout", "0s"); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
}
