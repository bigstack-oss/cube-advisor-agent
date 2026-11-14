package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const settings = `cubesys.management = eth0
cubesys.storage = eth1
cubesys.provider = eth2
cubesys.provider.extra = eth3
net.if.addr.eth0 = 10.32.1.5
net.if.mask.eth0 = 255.255.0.0
net.if.addr.eth1 = 172.16.0.5
net.if.mask.eth1 = 255.255.255.0
net.if.addr.eth2 = 192.168.50.5
net.if.mask.eth2 = 24
net.if.addr.eth3 = 8.8.8.1
net.if.mask.eth3 = 255.255.255.0
cubesys.control.vip = 10.40.0.9
`

// Provider networks carry VM traffic, so their subnets are refused.
func TestTheGuardAllowsOnlyTheClusterNetworksAndLoopback(t *testing.T) {
	g := GuardFromSettings(ParseSettings(strings.NewReader(settings)), nil)
	for _, ok := range []string{"10.32.200.1", "172.16.0.9", "10.40.0.9", "127.0.0.1", "::1", "::ffff:10.32.1.1"} {
		if err := g.Check(netip.MustParseAddr(ok)); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for bad, why := range map[string]string{
		"8.8.8.8": "outside", "8.8.8.2": "outside", "10.40.0.10": "outside", "172.16.1.1": "outside",
		"192.168.50.77":   "outside the cluster's networks (net-ro reaches only the management and storage networks",
		"169.254.169.254": "link-local", "fe80::1": "link-local", "0.0.0.0": "usable",
		"224.0.0.1": "link-local", "239.1.1.1": "multicast", "255.255.255.255": "broadcast", "2001:db8::1": "outside",
	} {
		err := g.Check(netip.MustParseAddr(bad))
		if err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v, want refused (%s)", bad, err, why)
		}
	}
	// No settings: loopback only, and the refusal says why.
	var none NetGuard
	if err := none.Check(netip.MustParseAddr("10.32.1.1")); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("empty guard: %v", err)
	}
	if err := none.Check(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("empty guard refused loopback: %v", err)
	}
}

func TestNetArgsAreTypedOnly(t *testing.T) {
	good := map[string]NetRequest{
		"zk c1 dump":                          {Kind: "zk", Host: "c1", Word: "dump", Port: 2181, Repeat: 1},
		"zk 10.32.1.5 ruok --newline":         {Kind: "zk", Host: "10.32.1.5", Word: "ruok", Port: 2181, Repeat: 1, Newline: true},
		"zk c1 mntr --repeat 200 --port 2182": {Kind: "zk", Host: "c1", Word: "mntr", Port: 2182, Repeat: 200},
		"tcp c1.lab 3306 --repeat 5":          {Kind: "tcp", Host: "c1.lab", Port: 3306, Repeat: 5},
		"ping c1 -c 5":                        {Kind: "ping", Host: "c1", Count: 5, Repeat: 1},
		"ping c1":                             {Kind: "ping", Host: "c1", Count: 3, Repeat: 1},
		"dns c1":                              {Kind: "dns", Host: "c1", Repeat: 1},
	}
	for in, want := range good {
		got, err := ParseNetArgs(strings.Fields(in))
		if err != nil {
			t.Errorf("%q refused: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q = %+v, want %+v", in, got, want)
		}
	}
	h, err := ParseNetArgs([]string{"http", "--head", "https://10.32.1.5:8443/v3?x=1"})
	if err != nil || !h.Head || h.Host != "10.32.1.5" {
		t.Errorf("http: %+v %v", h, err)
	}
	for _, bad := range [][]string{
		{}, {"nc", "c1", "2181"}, {"zk", "c1", "kill"}, {"zk", "c1", "wchp"}, {"zk", "c1;id", "dump"},
		{"zk", "-oProxyCommand=x", "dump"}, {"zk", "c1", "dump", "extra"}, {"zk", "c1", "dump", "--repeat", "1001"},
		{"zk", "c1", "dump", "--repeat", "0"}, {"zk", "c1", "dump", "--repeat"}, {"zk", "c1", "dump", "--port", "0"},
		{"zk", "c1", "dump", "--data", "x"}, {"zk", "$(id)", "dump"}, {"tcp", "c1", "99999"}, {"tcp", "c1", "22", "--newline"},
		{"tcp", "c1", "x"}, {"http", "file:///etc/passwd"}, {"http", "http://u:p@c1/"}, {"http", "http://c1/ x"},
		{"http", "gopher://c1/"}, {"http", "http://c1/", "-X", "POST"}, {"http", "http://c1/", "--data", "a"},
		{"http", "http://c1/\r\nX: y"}, {"ping", "c1", "-c", "21"}, {"ping", "c1", "-f"}, {"dns", "a b"},
		{"dns", "`id`"}, {"zk", "c1 dump"},
	} {
		if r, err := ParseNetArgs(bad); err == nil {
			t.Errorf("%q passed as %+v", bad, r)
		}
	}
}

// zkFake records what each connection sent and answers with reply(n).
type zkFake struct {
	addr string
	n    atomic.Int32
	mu   sync.Mutex
	got  [][]byte
}

func startZK(t *testing.T, reply func(n int, got []byte) []byte) *zkFake {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &zkFake{addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n := int(f.n.Add(1))
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				got, _ := io.ReadAll(c)
				f.mu.Lock()
				f.got = append(f.got, got)
				f.mu.Unlock()
				if r := reply(n, got); r != nil {
					_, _ = c.Write(r)
				} else {
					time.Sleep(time.Hour) // never answer, never close
				}
			}()
		}
	}()
	return f
}

func netServer(opts ...func(*Server)) *Server {
	s := &Server{NetGuard: func(context.Context) (NetGuard, error) {
		return GuardFromSettings(ParseSettings(strings.NewReader(settings)), nil), nil
	}}
	for _, o := range opts {
		o(s)
	}
	return s
}

func run(t *testing.T, s *Server, args ...string) (string, error) {
	t.Helper()
	req, err := ParseNetArgs(args)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	out, err := s.RunNet(context.Background(), req)
	return string(out), err
}

func TestZKSendsExactlyTheWord(t *testing.T) {
	f := startZK(t, func(_ int, got []byte) []byte { return []byte(fmt.Sprintf("got %q", got)) })
	host, port, _ := net.SplitHostPort(f.addr)
	s := netServer()
	out, err := run(t, s, "zk", host, "dump", "--port", port)
	if err != nil || !strings.Contains(out, `got "dump"`) || !strings.Contains(out, "(4 bytes sent)") {
		t.Fatalf("default: %q %v", out, err)
	}
	out, err = run(t, s, "zk", host, "srvr", "--port", port, "--newline")
	if err != nil || !strings.Contains(out, `got "srvr\n"`) || !strings.Contains(out, "(5 bytes sent)") {
		t.Fatalf("--newline: %q %v", out, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !bytes.Equal(f.got[0], []byte("dump")) || !bytes.Equal(f.got[1], []byte("srvr\n")) {
		t.Errorf("server saw %q", f.got)
	}
}

func TestZKRepeatCountsEmptyReplies(t *testing.T) {
	f := startZK(t, func(n int, _ []byte) []byte {
		if n%4 == 0 {
			return []byte{} // closes with nothing
		}
		return []byte("Zookeeper version: 3.8\n")
	})
	host, port, _ := net.SplitHostPort(f.addr)
	out, err := run(t, netServer(), "zk", host, "srvr", "--port", port, "--repeat", "20")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"x20 (4 bytes sent each): 15 non-empty, 5 empty, 0 errors", "time ms: min ", "p95 ", "first non-empty reply:\nZookeeper version"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestZKTimesOutAndCapsTheReply(t *testing.T) {
	old := NetProbeTimeout
	NetProbeTimeout = 400 * time.Millisecond
	t.Cleanup(func() { NetProbeTimeout = old })
	silent := startZK(t, func(int, []byte) []byte { return nil })
	host, port, _ := net.SplitHostPort(silent.addr)
	start := time.Now()
	out, err := run(t, netServer(), "zk", host, "dump", "--port", port)
	if err != nil || !strings.Contains(out, "0 bytes back") || !strings.Contains(out, "no close from the server") {
		t.Errorf("silent: %q %v", out, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	big := startZK(t, func(int, []byte) []byte { return bytes.Repeat([]byte("x"), 100<<10) })
	host, port, _ = net.SplitHostPort(big.addr)
	out, _ = run(t, netServer(), "zk", host, "dump", "--port", port)
	if !strings.Contains(out, "[reply cut at 65536 bytes]") || len(out) > NetReplyCap+500 {
		t.Errorf("big reply not cut: %d bytes", len(out))
	}
}

func TestTCPConnectTimings(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	out, _ := run(t, netServer(), "tcp", host, port, "--repeat", "3")
	if !strings.Contains(out, "x3: 3 connected, 0 failed") || !strings.Contains(out, "time ms:") {
		t.Errorf("open port: %s", out)
	}
	l.Close()
	out, _ = run(t, netServer(), "tcp", host, port)
	if !strings.Contains(out, "x1: 0 connected, 1 failed") || !strings.Contains(out, "error x1:") {
		t.Errorf("closed port: %s", out)
	}
}

func TestDestinationsOutsideTheClusterAreNeverDialled(t *testing.T) {
	var pinged atomic.Int32
	s := netServer(func(s *Server) {
		s.LookupHost = func(_ context.Context, h string) ([]netip.Addr, error) {
			switch h {
			case "evil.example":
				return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
			case "c1":
				return []netip.Addr{netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("10.32.1.6")}, nil
			}
			return nil, fmt.Errorf("no such host")
		}
		s.PingRun = func(_ context.Context, ip netip.Addr, n int) ([]byte, error) {
			pinged.Add(1)
			return []byte(fmt.Sprintf("pinged %s x%d", ip, n)), nil
		}
	})
	for _, args := range [][]string{
		{"zk", "8.8.8.8", "dump"}, {"tcp", "169.254.169.254", "80"}, {"tcp", "evil.example", "443"},
		{"ping", "1.1.1.1"}, {"ping", "fe80::1"}, {"http", "http://169.254.169.254/latest/meta-data/"},
		{"http", "http://evil.example/"}, {"tcp", "nosuch", "22"},
	} {
		out, err := run(t, s, args...)
		if _, ok := err.(*netRefusal); !ok {
			t.Errorf("%v: %q %v, want a refusal", args, out, err)
		}
	}
	if pinged.Load() != 0 {
		t.Fatal("a refused ping ran")
	}
	// A name with one cluster address uses that address.
	out, err := run(t, s, "ping", "c1", "-c", "2")
	if err != nil || out != "pinged 10.32.1.6 x2" {
		t.Errorf("ping c1: %q %v", out, err)
	}
	out, _ = run(t, s, "dns", "c1")
	if !strings.Contains(out, "2001:db8::5\toutside") || !strings.Contains(out, "10.32.1.6\tin the cluster") {
		t.Errorf("dns: %q", out)
	}
}

func TestANodeNameUsesItsNodeAddressNotLoopback(t *testing.T) {
	both := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.32.1.6")}
	s := netServer(func(s *Server) {
		s.Nodes = func(context.Context) ([]string, error) { return []string{"c1", "c2"}, nil }
		s.LookupHost = func(context.Context, string) ([]netip.Addr, error) { return slices.Clone(both), nil }
		s.PingRun = func(_ context.Context, ip netip.Addr, _ int) ([]byte, error) { return []byte(ip.String()), nil }
	})
	for host, want := range map[string]string{"c1": "10.32.1.6", "C1": "10.32.1.6", "other": "::1"} {
		if out, err := run(t, s, "ping", host); err != nil || out != want {
			t.Errorf("ping %s: %q %v, want %s", host, out, err, want)
		}
	}
}

func TestTheGuardedResolverReadsTheHostsFile(t *testing.T) {
	s := netServer()
	g, _ := s.netGuard(context.Background())
	addrs, err := s.lookup(context.Background(), g, "localhost")
	if err != nil || len(addrs) == 0 || !addrs[0].IsLoopback() {
		t.Errorf("localhost: %v %v", addrs, err)
	}
}

func TestHTTPGetHeadCapsAndRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte("y"), 300<<10))
		case "/meta":
			http.Redirect(w, r, "http://169.254.169.254/latest/", http.StatusFound)
		case "/hop":
			http.Redirect(w, r, "/ok", http.StatusFound)
		default:
			if r.Method != http.MethodGet && r.Method != http.MethodHead || r.ContentLength > 0 {
				w.WriteHeader(http.StatusTeapot)
			}
			w.Header().Set("Set-Cookie", "secret=1")
			fmt.Fprintf(w, "%s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	s := netServer()
	out, err := run(t, s, "http", srv.URL+"/ok")
	if err != nil || !strings.HasPrefix(out, "HTTP/1.1 200 OK\n"+plainHTTP+"\n") || !strings.HasSuffix(out, "GET /ok") || strings.Contains(out, "secret") {
		t.Errorf("get: %q %v", out, err)
	}
	out, err = run(t, s, "http", "--head", srv.URL+"/ok")
	if err != nil || !strings.HasPrefix(out, "HTTP/1.1 200 OK") || strings.Contains(out, "HEAD /ok") {
		t.Errorf("head: %q %v", out, err)
	}
	out, _ = run(t, s, "http", srv.URL+"/big")
	if !strings.Contains(out, "[body cut at 262144 bytes]") || len(out) > NetHTTPBodyCap+1000 {
		t.Errorf("big body not cut: %d", len(out))
	}
	out, err = run(t, s, "http", srv.URL+"/hop")
	if err != nil || !strings.Contains(out, "# after redirects: ") || !strings.HasSuffix(out, "GET /ok") {
		t.Errorf("redirect in range: %q %v", out, err)
	}
	out, err = run(t, s, "http", srv.URL+"/meta")
	if _, ok := err.(*netRefusal); !ok || !strings.Contains(err.Error(), "link-local") {
		t.Errorf("redirect off range: %q %v", out, err)
	}
}

func TestNetBrokerRefusesAndAudits(t *testing.T) {
	_, audit, dir := start(t, http.NotFoundHandler(), func(s *Server) {
		s.NetGuard = netServer().NetGuard
	})
	c := unixClient(filepath.Join(dir, "net.sock"))
	post := func(args ...string) (int, string) {
		b, _ := json.Marshal(map[string][]string{"args": args})
		resp, err := c.Post("http://broker/run", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, body := post("zk", "8.8.8.8", "dump"); code != http.StatusForbidden || !strings.Contains(body, "outside the cluster") {
		t.Errorf("outside: %d %q", code, body)
	}
	if code, body := post("zk", "c1", "kill"); code != http.StatusBadRequest {
		t.Errorf("bad word: %d %q", code, body)
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if len(audit.calls) != 2 {
		t.Fatalf("audited %d", len(audit.calls))
	}
	for _, a := range audit.calls {
		if a.Allowed || a.Tool != "broker:net" {
			t.Errorf("audit %+v", a)
		}
	}
}

func TestNetClientReachesTheBroker(t *testing.T) {
	for _, b := range []string{"curl", "python3"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip("no " + b)
		}
	}
	_, _, dir := start(t, http.NotFoundHandler(), func(s *Server) { s.NetGuard = netServer().NetGuard })
	f := startZK(t, func(_ int, got []byte) []byte { return []byte("imok") })
	host, port, _ := net.SplitHostPort(f.addr)
	out, err := exec.Command(filepath.Join(dir, "bin", "net-ro"), "zk", host, "ruok", "--port", port).CombinedOutput()
	if err != nil || !strings.HasSuffix(string(out), "imok") {
		t.Fatalf("net-ro zk: %q %v", out, err)
	}
	out, _ = exec.Command(filepath.Join(dir, "bin", "net-ro")).CombinedOutput()
	if !strings.Contains(string(out), "net-ro zk HOST") {
		t.Errorf("usage: %q", out)
	}
}

// https is not verified, and every answer says so, redirected or not.
func TestHTTPSAnswersSayTLSIsNotVerified(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/ok", http.StatusFound)
	}))
	t.Cleanup(plain.Close)
	s := netServer()
	for _, u := range []string{srv.URL + "/ok", srv.URL + "/hop", plain.URL + "/up"} {
		for _, args := range [][]string{{"http", u}, {"http", "--head", u}} {
			out, err := run(t, s, args...)
			if err != nil || !strings.HasPrefix(out, "HTTP/1.1 200 OK\n"+tlsNotVerified+"\n") {
				t.Errorf("%v: %q %v", args, out, err)
			}
		}
	}
}
