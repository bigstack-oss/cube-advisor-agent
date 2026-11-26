package console

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/openstack"
)

const (
	netA = "69a05958-533e-4b4a-a9b1-88ed1e06f6e6"
	lbPt = "cf2cd631-ad1e-4c02-8f54-a3c6f0c6c976"
)

type fakeNeutron struct{ srv *httptest.Server }

func (f fakeNeutron) Endpoint(context.Context, string) (string, string, error) {
	return f.srv.URL, "tok", nil
}
func (f fakeNeutron) HTTP() *http.Client { return f.srv.Client() }

// neutron serves the three reads Plan makes. legs is the mgr-port answer.
func neutron(t *testing.T, legs string) fakeNeutron {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "tok" {
			t.Errorf("no token on %s", r.URL)
		}
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/v2.0/floatingips" && q.Get("floating_ip_address") == "10.32.21.32":
			io.WriteString(w, `{"floatingips":[{"fixed_ip_address":"192.168.1.103","port_id":"`+lbPt+`"}]}`)
		case r.URL.Path == "/v2.0/floatingips":
			io.WriteString(w, `{"floatingips":[]}`)
		case r.URL.Path == "/v2.0/ports/"+lbPt:
			io.WriteString(w, `{"port":{"network_id":"`+netA+`"}}`)
		case r.URL.Path == "/v2.0/ports" && q.Get("fixed_ips") == "ip_address=192.168.1.236":
			// three tenant networks reuse the CIDR
			io.WriteString(w, `{"ports":[{"network_id":"`+netA+`"},{"network_id":"93b8abe3-50dd-4bfb-bcac-90b47de29575"}]}`)
		case r.URL.Path == "/v2.0/ports" && q.Get("fixed_ips") == "ip_address=10.91.0.85":
			io.WriteString(w, `{"ports":[{"network_id":"`+netA+`"}]}`)
		case r.URL.Path == "/v2.0/ports" && q.Get("device_owner") == MgrPortOwner && q.Get("network_id") == netA:
			io.WriteString(w, legs)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return fakeNeutron{srv}
}

const oneLeg = `{"ports":[
 {"name":"other","status":"ACTIVE","binding:host_id":"x"},
 {"name":"cmp1-` + netA + `","status":"DOWN","binding:host_id":"cmp1"},
 {"name":"cmp2-` + netA + `","status":"ACTIVE","binding:host_id":"cmp2"}]}`

func TestPlanFollowsAFloatingIPToItsNetworksLeg(t *testing.T) {
	r := &NetnsRelay{OpenStack: neutron(t, oneLeg)}
	p, err := r.Plan(context.Background(), "10.32.21.32:443")
	if err != nil {
		t.Fatal(err)
	}
	want := RelayPlan{Node: "cmp2", Netns: "mgr-69a05958", IP: "192.168.1.103", Port: "443"}
	if p != want {
		t.Fatalf("plan = %+v, want %+v", p, want)
	}
}

func TestPlanTakesAFixedAddressOnlyWhenOnePortHasIt(t *testing.T) {
	r := &NetnsRelay{OpenStack: neutron(t, oneLeg)}
	if _, err := r.Plan(context.Background(), "192.168.1.236:443"); !errors.Is(err, ErrNoRelay) {
		t.Fatalf("an address on two networks must be refused, got %v", err)
	}
	p, err := r.Plan(context.Background(), "10.91.0.85:8443")
	if err != nil || p.IP != "10.91.0.85" || p.Port != "8443" {
		t.Fatalf("plan = %+v, %v", p, err)
	}
}

func TestPlanRefuses(t *testing.T) {
	r := &NetnsRelay{OpenStack: neutron(t, `{"ports":[]}`)}
	for _, hp := range []string{"10.32.21.32:443", "0.0.0.0:443", "127.0.0.1:22", "example.com:443", "[::1]:443", "10.32.21.32:http"} {
		if _, err := r.Plan(context.Background(), hp); err == nil {
			t.Errorf("%s: planned a relay", hp)
		}
	}
	if _, err := (&NetnsRelay{}).Plan(context.Background(), "10.32.21.32:443"); !errors.Is(err, ErrNoRelay) {
		t.Errorf("no credential: %v", err)
	}
}

func TestPlanDropsALegWhoseHostCouldBeAnSSHOption(t *testing.T) {
	legs := `{"ports":[{"name":"x-` + netA + `","status":"ACTIVE","binding:host_id":"-oProxyCommand=id"}]}`
	r := &NetnsRelay{OpenStack: neutron(t, legs)}
	if _, err := r.Plan(context.Background(), "10.32.21.32:443"); !errors.Is(err, ErrNoRelay) {
		t.Fatalf("got %v", err)
	}
}

func TestArgvIsLocalOrOverSSH(t *testing.T) {
	p := RelayPlan{Node: "cmp2", Netns: "mgr-69a05958", IP: "192.168.1.103", Port: "443"}
	local := strings.Join(p.Argv(true), " ")
	if local != "ip netns exec mgr-69a05958 socat - TCP4:192.168.1.103:443,connect-timeout=5" {
		t.Fatalf("local argv: %s", local)
	}
	remote := p.Argv(false)
	if remote[0] != "ssh" || !strings.HasSuffix(strings.Join(remote, " "), " root@cmp2 "+local) {
		t.Fatalf("remote argv: %v", remote)
	}
}

func TestArgvSharedRidesOneConnectionPerNode(t *testing.T) {
	p := RelayPlan{Node: "cmp2", Netns: "mgr-69a05958", IP: "192.168.1.103", Port: "443"}
	shared := strings.Join(p.ArgvShared("/run/x"), " ")
	for _, want := range []string{"ControlMaster=auto", "ControlPath=/run/x/%C", "ControlPersist=60", " root@cmp2 ip netns exec "} {
		if !strings.Contains(shared, want) {
			t.Errorf("shared argv lacks %s: %s", want, shared)
		}
	}
	if strings.Contains(shared, "ControlPath=none") || !strings.Contains(strings.Join(p.Argv(false), " "), "ControlPath=none") {
		t.Fatalf("only the unshared argv turns sharing off: %s", shared)
	}
}

func TestDialSharesUpToTheSessionLimit(t *testing.T) {
	var got []string
	r := &NetnsRelay{OpenStack: neutron(t, oneLeg), Hostname: "ctl1", ControlDir: "/run/x",
		start: func(argv []string) (net.Conn, error) { got = argv; a, _ := net.Pipe(); return a, nil }}
	isShared := func() bool { return strings.Contains(strings.Join(got, " "), "ControlMaster=auto") }
	var conns []net.Conn
	for i := 0; i < sharedSessions; i++ {
		c, err := r.Dial(context.Background(), "10.32.21.32:443")
		if err != nil || !isShared() {
			t.Fatalf("relay %d: shared=%v err=%v", i, isShared(), err)
		}
		conns = append(conns, c)
	}
	// one more than sshd allows on a connection gets its own
	if _, err := r.Dial(context.Background(), "10.32.21.32:443"); err != nil || isShared() {
		t.Fatalf("over the limit: shared=%v err=%v", isShared(), err)
	}
	conns[0].Close()
	conns[0].Close() // a second close frees nothing more
	if _, _ = r.Dial(context.Background(), "10.32.21.32:443"); !isShared() {
		t.Fatal("a closed relay did not free its place")
	}
	if _, _ = r.Dial(context.Background(), "10.32.21.32:443"); isShared() {
		t.Fatal("a double close freed two places")
	}
	// the node that holds the leg never goes over SSH
	r.Hostname = "cmp2"
	if _, _ = r.Dial(context.Background(), "10.32.21.32:443"); got[0] != "ip" {
		t.Fatalf("argv %v", got)
	}
	// a failed start gives its place back
	r2 := &NetnsRelay{OpenStack: neutron(t, oneLeg), Hostname: "ctl1", ControlDir: "/run/x",
		start: func([]string) (net.Conn, error) { return nil, errors.New("no ssh") }}
	for i := 0; i <= sharedSessions; i++ {
		r2.Dial(context.Background(), "10.32.21.32:443")
	}
	if r2.shared["cmp2"] != 0 {
		t.Fatalf("places leaked: %d", r2.shared["cmp2"])
	}
}

func TestDialRunsLocallyOnTheNodeThatHoldsTheLeg(t *testing.T) {
	var got []string
	var audited RelayPlan
	r := &NetnsRelay{OpenStack: neutron(t, oneLeg), Hostname: "CMP2",
		Audit: func(_ string, p RelayPlan, _ error) { audited = p },
		start: func(argv []string) (net.Conn, error) { got = argv; a, _ := net.Pipe(); return a, nil }}
	if _, err := r.Dial(context.Background(), "10.32.21.32:443"); err != nil {
		t.Fatal(err)
	}
	if got[0] != "ip" || audited.Node != "cmp2" {
		t.Fatalf("argv %v, audited %+v", got, audited)
	}
	r.Hostname = "ctl1"
	if _, _ = r.Dial(context.Background(), "10.32.21.32:443"); got[0] != "ssh" {
		t.Fatalf("argv %v", got)
	}
}

func TestFallbackRelaysOnlyWhenThereIsNoRoute(t *testing.T) {
	relayed := 0
	r := &NetnsRelay{OpenStack: neutron(t, oneLeg),
		start: func([]string) (net.Conn, error) { relayed++; a, _ := net.Pipe(); return a, nil }}
	directs := 0
	var directErr error
	d := FallbackDialer(func(context.Context, string) (net.Conn, error) { directs++; return nil, directErr }, r)

	directErr = syscall.ECONNREFUSED
	if _, err := d(context.Background(), "10.32.21.32:443"); !errors.Is(err, syscall.ECONNREFUSED) || relayed != 0 {
		t.Fatalf("refused must not relay: %v, relayed %d", err, relayed)
	}
	directErr = &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}
	if _, err := d(context.Background(), "10.32.21.32:443"); err != nil || relayed != 1 {
		t.Fatalf("no route must relay: %v, relayed %d", err, relayed)
	}
	// the next open goes straight to the relay
	before := directs
	if _, err := d(context.Background(), "10.32.21.32:443"); err != nil || relayed != 2 || directs != before {
		t.Fatalf("relayed %d, directs %d→%d, %v", relayed, before, directs, err)
	}
}

func TestProcConnPipesAndEndsTheProcess(t *testing.T) {
	c, err := startProc([]string{"cat"})
	if err != nil {
		t.Skip(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("%q %v", buf, err)
	}
	c.Close()
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, c); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay outlived its connection")
	}
}

// TestLabRelay opens a real relay on a CubeCOS node:
//
//	ADVISOR_RELAY_LAB=10.32.21.32:443 ADVISOR_RELAY_HOST=<hostname> ./console.test -test.run LabRelay -test.v
func TestLabRelay(t *testing.T) {
	target := os.Getenv("ADVISOR_RELAY_LAB")
	if target == "" {
		t.Skip("ADVISOR_RELAY_LAB not set")
	}
	r := &NetnsRelay{OpenStack: openstack.NewAdmin(openstack.OpenrcPath), Hostname: os.Getenv("ADVISOR_RELAY_HOST")}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p, err := r.Plan(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plan: %+v argv: %v", p, p.Argv(strings.EqualFold(p.Node, r.Hostname)))
	c, err := r.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Plain HTTP on :80 answers without TLS; on :443 nginx answers 400 in clear.
	io.WriteString(c, "GET /auth/realms/master HTTP/1.0\r\nHost: relay-test\r\n\r\n")
	b, _ := io.ReadAll(io.LimitReader(c, 400))
	if !strings.HasPrefix(string(b), "HTTP/1.") {
		t.Fatalf("no HTTP answer through the relay: %q", b)
	}
	t.Logf("answer: %q", strings.SplitN(string(b), "\r\n", 2)[0])
}
