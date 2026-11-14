package broker

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Limits on one net-ro probe.
const (
	NetHTTPTimeout  = 10 * time.Second
	NetReplyCap     = 64 << 10
	NetHTTPBodyCap  = 256 << 10
	NetOutputCap    = 1 << 20
	NetMaxRepeat    = 1000
	NetMaxPing      = 20
	NetMaxRedirects = 3
	netGuardTTL     = time.Minute
)

// NetProbeTimeout bounds one zk or tcp probe.
var NetProbeTimeout = 3 * time.Second

// SettingsPath is CubeCOS's settings file, the guard's source of truth.
var SettingsPath = "/etc/settings.txt"

// zkWords are the ZooKeeper four-letter words net-ro sends; all only read.
var zkWords = []string{"srvr", "dump", "ruok", "mntr", "stat", "conf", "envi"}

// NetGuard holds the cluster's own networks: net-ro reaches nothing else.
type NetGuard struct {
	Prefixes []netip.Prefix
	Addrs    []netip.Addr
}

// Check allows loopback (this node's own services) and addresses inside the
// cluster's networks or on its address list. Link-local (cloud metadata),
// multicast and unspecified addresses are always refused.
func (g NetGuard) Check(a netip.Addr) error {
	a = a.Unmap()
	switch {
	case !a.IsValid() || a.IsUnspecified():
		return fmt.Errorf("%s is not a usable address", a)
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast():
		return fmt.Errorf("%s is link-local (metadata and other non-cluster services live there)", a)
	case a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255"):
		return fmt.Errorf("%s is a multicast or broadcast address", a)
	case a.IsLoopback():
		return nil
	}
	if slices.Contains(g.Addrs, a) {
		return nil
	}
	for _, p := range g.Prefixes {
		if p.Contains(a) {
			return nil
		}
	}
	if len(g.Prefixes) == 0 && len(g.Addrs) == 0 {
		return fmt.Errorf("%s refused: this node's cluster networks are unknown (no usable %s)", a, SettingsPath)
	}
	return fmt.Errorf("%s is outside the cluster's networks (%s)", a, guardScope)
}

// ParseSettings reads `key = value` lines.
func ParseSettings(r io.Reader) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// guardScope names what the guard allows, for refusals.
const guardScope = "net-ro reaches only the management and storage networks, the cluster's VIP and node addresses, and loopback"

// GuardFromSettings builds the guard from CubeCOS settings: the subnets of
// the management and storage interfaces (net.if.addr/mask.<if>), never the
// provider networks, which carry VM traffic,
// and the control VIP and the control, storage and controller addresses.
// ifaceAddrs, if set, adds the live prefixes of those same interfaces.
func GuardFromSettings(s map[string]string, ifaceAddrs func(name string) []netip.Prefix) NetGuard {
	var g NetGuard
	for _, key := range []string{"cubesys.management", "cubesys.storage"} {
		for _, ifc := range splitList(s[key]) {
			if p, ok := settingsPrefix(s["net.if.addr."+ifc], s["net.if.mask."+ifc]); ok {
				g.Prefixes = append(g.Prefixes, p)
			}
			if ifaceAddrs != nil {
				g.Prefixes = append(g.Prefixes, ifaceAddrs(ifc)...)
			}
		}
	}
	for _, key := range []string{"cubesys.control.vip", "cubesys.control.addrs", "cubesys.storage.addrs", "cubesys.controller.ip"} {
		for _, v := range splitList(s[key]) {
			if a, err := netip.ParseAddr(v); err == nil {
				g.Addrs = append(g.Addrs, a.Unmap())
			}
		}
	}
	return g
}

func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

// settingsPrefix takes an address and a dotted or numeric mask.
func settingsPrefix(addr, mask string) (netip.Prefix, bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil || mask == "" {
		return netip.Prefix{}, false
	}
	bits, err := strconv.Atoi(mask)
	if err != nil {
		m := net.ParseIP(mask).To4()
		if m == nil {
			return netip.Prefix{}, false
		}
		ones, size := net.IPMask(m).Size()
		if size == 0 {
			return netip.Prefix{}, false
		}
		bits = ones
	}
	p, err := a.Unmap().Prefix(bits)
	if err != nil || bits == 0 {
		return netip.Prefix{}, false
	}
	return p, true
}

// liveIfacePrefixes are the global unicast prefixes on one interface.
func liveIfacePrefixes(name string) []netip.Prefix {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, _ := ifc.Addrs()
	var out []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		ones, _ := n.Mask.Size()
		if ok && ip.Unmap().IsGlobalUnicast() && ones > 0 {
			if p, err := ip.Unmap().Prefix(ones); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// LocalNetGuard reads the node's settings and live interfaces, and adds the
// addresses the cluster's node names resolve to through /etc/hosts.
func (s *Server) LocalNetGuard(ctx context.Context) (NetGuard, error) {
	f, err := os.Open(SettingsPath)
	if err != nil {
		return NetGuard{}, nil // fail closed: loopback only
	}
	defer f.Close()
	g := GuardFromSettings(ParseSettings(f), liveIfacePrefixes)
	if nodes, err := s.clusterNodes(ctx); err == nil {
		for _, n := range nodes {
			g.Addrs = append(g.Addrs, hostsLookup(n)...)
		}
	}
	return g, nil
}

// HostsPath is the hosts file node names are resolved from.
var HostsPath = "/etc/hosts"

func hostsLookup(name string) []netip.Addr {
	b, err := os.ReadFile(HostsPath)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err == nil && slices.ContainsFunc(f[1:], func(h string) bool { return strings.EqualFold(h, name) }) {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// netGuard is the cached guard.
func (s *Server) netGuard(ctx context.Context) (NetGuard, error) {
	s.guardMu.Lock()
	defer s.guardMu.Unlock()
	if s.guardSet && time.Since(s.guardAt) < netGuardTTL {
		return s.guard, nil
	}
	f := s.NetGuard
	if f == nil {
		f = s.LocalNetGuard
	}
	g, err := f(ctx)
	if err != nil {
		return NetGuard{}, err
	}
	s.guard, s.guardAt, s.guardSet = g, time.Now(), true
	return g, nil
}

// lookup resolves host to addresses; nameservers outside the guard are not
// asked. An IP literal is returned as is.
func (s *Server) lookup(ctx context.Context, g NetGuard, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	if s.LookupHost != nil {
		return s.LookupHost(ctx, host)
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, err
		}
		if err := g.Check(ap.Addr()); err != nil {
			return nil, fmt.Errorf("nameserver %w", err)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}}
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, a := range ips {
		out = append(out, a.Unmap())
	}
	return out, nil
}

// target resolves host and keeps the addresses the guard allows; none
// allowed is a refusal. A cluster node's name uses its node address, not
// the loopback entry /etc/hosts gives the node's own name.
func (s *Server) target(ctx context.Context, g NetGuard, host string) (netip.Addr, error) {
	addrs, err := s.lookup(ctx, g, host)
	if err != nil {
		return netip.Addr{}, &netRefusal{fmt.Sprintf("%s: cannot resolve: %v", host, err)}
	}
	if s.isNode(ctx, host) {
		slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
			return cmp.Compare(boolInt(a.IsLoopback()), boolInt(b.IsLoopback()))
		})
	}
	var why []string
	for _, a := range addrs {
		if err := g.Check(a); err == nil {
			return a, nil
		} else {
			why = append(why, err.Error())
		}
	}
	if len(why) == 0 {
		return netip.Addr{}, &netRefusal{host + ": no addresses"}
	}
	return netip.Addr{}, &netRefusal{"refused: " + host + ": " + strings.Join(why, "; ")}
}

func (s *Server) isNode(ctx context.Context, host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	nodes, err := s.clusterNodes(ctx)
	return err == nil && slices.ContainsFunc(nodes, func(n string) bool { return strings.EqualFold(n, host) })
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type netRefusal struct{ msg string }

func (e *netRefusal) Error() string { return e.msg }

// NetRequest is one parsed net-ro call.
type NetRequest struct {
	Kind    string // zk, tcp, http, ping, dns
	Host    string
	Port    int
	Word    string // zk
	Newline bool   // zk
	Repeat  int    // zk, tcp
	URL     *url.URL
	Head    bool // http
	Count   int  // ping
}

// ParseNetArgs validates a net-ro call; only typed values pass.
func ParseNetArgs(args []string) (NetRequest, error) {
	if len(args) == 0 {
		return NetRequest{}, errors.New("usage: net-ro zk|tcp|http|ping|dns ...")
	}
	req := NetRequest{Kind: args[0], Repeat: 1}
	var pos []string
	intFlag := func(rest []string, i *int, name string, lo, hi int) (int, error) {
		if *i+1 >= len(rest) {
			return 0, fmt.Errorf("%s needs a number", name)
		}
		*i++
		n, err := strconv.Atoi(rest[*i])
		if err != nil || n < lo || n > hi {
			return 0, fmt.Errorf("%s must be a number from %d to %d", name, lo, hi)
		}
		return n, nil
	}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		var err error
		switch {
		case a == "--newline" && req.Kind == "zk":
			req.Newline = true
		case a == "--repeat" && (req.Kind == "zk" || req.Kind == "tcp"):
			req.Repeat, err = intFlag(rest, &i, "--repeat", 1, NetMaxRepeat)
		case a == "--port" && req.Kind == "zk":
			req.Port, err = intFlag(rest, &i, "--port", 1, 65535)
		case a == "-c" && req.Kind == "ping":
			req.Count, err = intFlag(rest, &i, "-c", 1, NetMaxPing)
		case a == "--head" && req.Kind == "http":
			req.Head = true
		case strings.HasPrefix(a, "-"):
			return NetRequest{}, fmt.Errorf("unknown option %q for net-ro %s", a, req.Kind)
		default:
			pos = append(pos, a)
		}
		if err != nil {
			return NetRequest{}, err
		}
	}
	want := map[string]int{"zk": 2, "tcp": 2, "http": 1, "ping": 1, "dns": 1}
	n, ok := want[req.Kind]
	if !ok {
		return NetRequest{}, fmt.Errorf("unknown probe %q: use zk, tcp, http, ping or dns", req.Kind)
	}
	if len(pos) != n {
		return NetRequest{}, fmt.Errorf("net-ro %s takes %d argument(s), got %d", req.Kind, n, len(pos))
	}
	if req.Kind == "http" {
		u, err := checkProbeURL(pos[0])
		if err != nil {
			return NetRequest{}, err
		}
		req.URL, req.Host = u, u.Hostname()
		return req, nil
	}
	if !validHost(pos[0]) {
		return NetRequest{}, fmt.Errorf("%q is not a host name or address", pos[0])
	}
	req.Host = pos[0]
	switch req.Kind {
	case "zk":
		if !slices.Contains(zkWords, pos[1]) {
			return NetRequest{}, fmt.Errorf("zk sends only %s", strings.Join(zkWords, ", "))
		}
		req.Word = pos[1]
		if req.Port == 0 {
			req.Port = 2181
		}
	case "tcp":
		p, err := strconv.Atoi(pos[1])
		if err != nil || p < 1 || p > 65535 {
			return NetRequest{}, fmt.Errorf("port must be a number from 1 to 65535")
		}
		req.Port = p
	case "ping":
		if req.Count == 0 {
			req.Count = 3
		}
	}
	return req, nil
}

func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return hostName.MatchString(h)
}

func checkProbeURL(raw string) (*url.URL, error) {
	if len(raw) > 2048 || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return nil, errors.New("the URL is too long or has spaces or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("bad URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("only http:// and https:// URLs")
	}
	if u.User != nil {
		return nil, errors.New("credentials in the URL are not sent")
	}
	if !validHost(u.Hostname()) {
		return nil, fmt.Errorf("%q is not a host name or address", u.Hostname())
	}
	return u, nil
}

// net serves net-ro: POST {"args":[...]} to /run.
func (s *Server) net(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var in struct {
		Args []string `json:"args"`
	}
	args := map[string]string{}
	refuse := func(code int, why string) {
		s.record(r, "broker:net", args, false, why, started, 0)
		http.Error(w, why, code)
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&in) != nil {
		refuse(http.StatusBadRequest, `POST {"args":[...]}`)
		return
	}
	args["args"] = strings.Join(in.Args, " ")
	req, err := ParseNetArgs(in.Args)
	if err != nil {
		refuse(http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), CallTimeout)
	defer cancel()
	out, err := s.RunNet(ctx, req)
	var nr *netRefusal
	if errors.As(err, &nr) {
		refuse(http.StatusForbidden, nr.msg)
		return
	}
	if err != nil {
		out = append(out, ("error: " + err.Error() + "\n")...)
	}
	if len(out) > NetOutputCap {
		out = append(out[:NetOutputCap], fmt.Sprintf("\n[broker: answer cut at %d bytes]\n", NetOutputCap)...)
	}
	s.record(r, "broker:net", args, true, "", started, len(out))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}

// RunNet runs one validated probe. A *netRefusal error means nothing was sent.
func (s *Server) RunNet(ctx context.Context, req NetRequest) ([]byte, error) {
	g, err := s.netGuard(ctx)
	if err != nil {
		return nil, &netRefusal{"cluster networks: " + err.Error()}
	}
	if req.Kind == "dns" {
		return s.netDNS(ctx, g, req.Host)
	}
	ip, err := s.target(ctx, g, req.Host)
	if err != nil {
		return nil, err
	}
	switch req.Kind {
	case "zk":
		return s.netZK(ctx, req, ip), nil
	case "tcp":
		return s.netTCP(ctx, req, ip), nil
	case "http":
		return s.netHTTP(ctx, g, req)
	case "ping":
		run := s.PingRun
		if run == nil {
			run = localPing
		}
		return run(ctx, ip, req.Count)
	}
	return nil, &netRefusal{"unknown probe " + req.Kind}
}

func (s *Server) netDNS(ctx context.Context, g NetGuard, name string) ([]byte, error) {
	addrs, err := s.lookup(ctx, g, name)
	if err != nil {
		return nil, &netRefusal{fmt.Sprintf("%s: cannot resolve: %v", name, err)}
	}
	var b strings.Builder
	for _, a := range addrs {
		where := "in the cluster"
		if err := g.Check(a); err != nil {
			where = "outside the cluster's networks, net-ro will not reach it"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\n", name, a, where)
	}
	return []byte(b.String()), nil
}

// zkOnce sends the four-letter word and reads the reply until the server
// closes or the probe times out.
func zkOnce(ctx context.Context, addr string, payload []byte) ([]byte, time.Duration, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, NetProbeTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, time.Since(start), err
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	_ = c.SetDeadline(dl)
	if _, err := c.Write(payload); err != nil {
		return nil, time.Since(start), err
	}
	reply, err := io.ReadAll(io.LimitReader(c, NetReplyCap))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		err = fmt.Errorf("no close from the server within %s", NetProbeTimeout)
	}
	return reply, time.Since(start), err
}

func (s *Server) netZK(ctx context.Context, req NetRequest, ip netip.Addr) []byte {
	payload := []byte(req.Word)
	if req.Newline {
		payload = append(payload, '\n')
	}
	addr := netip.AddrPortFrom(ip, uint16(req.Port)).String()
	var b strings.Builder
	if req.Repeat == 1 {
		reply, took, err := zkOnce(ctx, addr, payload)
		fmt.Fprintf(&b, "# zk %s %s (%d bytes sent): %d bytes back in %s\n", addr, req.Word, len(payload), len(reply), ms(took))
		b.Write(reply)
		if len(reply) == NetReplyCap {
			fmt.Fprintf(&b, "\n[reply cut at %d bytes]\n", NetReplyCap)
		}
		if err != nil {
			fmt.Fprintf(&b, "\nerror: %v\n", err)
		}
		return []byte(b.String())
	}
	var st stats
	var first []byte
	for i := 0; i < req.Repeat && ctx.Err() == nil; i++ {
		reply, took, err := zkOnce(ctx, addr, payload)
		st.add(took, err, len(reply) > 0)
		if first == nil && len(reply) > 0 {
			first = reply
		}
	}
	fmt.Fprintf(&b, "zk %s %s x%d (%d bytes sent each): %d non-empty, %d empty, %d errors\n",
		addr, req.Word, st.n, len(payload), st.ok, st.n-st.ok, st.errs)
	st.write(&b, req.Repeat)
	if first != nil {
		fmt.Fprintf(&b, "first non-empty reply:\n%s", first)
	}
	return []byte(b.String())
}

func (s *Server) netTCP(ctx context.Context, req NetRequest, ip netip.Addr) []byte {
	addr := netip.AddrPortFrom(ip, uint16(req.Port)).String()
	var st stats
	for i := 0; i < req.Repeat && ctx.Err() == nil; i++ {
		start := time.Now()
		cctx, cancel := context.WithTimeout(ctx, NetProbeTimeout)
		var d net.Dialer
		c, err := d.DialContext(cctx, "tcp", addr)
		cancel()
		took := time.Since(start)
		if err == nil {
			c.Close()
		}
		st.add(took, err, err == nil)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "tcp %s x%d: %d connected, %d failed\n", addr, st.n, st.ok, st.n-st.ok)
	st.write(&b, req.Repeat)
	return []byte(b.String())
}

func (s *Server) netHTTP(ctx context.Context, g NetGuard, req NetRequest) ([]byte, error) {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip, err := s.target(ctx, g, host)
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	usedTLS := req.URL.Scheme == "https"
	c := &http.Client{
		Timeout: NetHTTPTimeout,
		Transport: &http.Transport{
			Proxy: nil, DialContext: dial, DisableKeepAlives: true,
			// Cluster services use self-signed certificates; nothing secret is sent.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: NetHTTPTimeout,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Scheme == "https" {
				usedTLS = true
			}
			if len(via) > NetMaxRedirects {
				return fmt.Errorf("more than %d redirects", NetMaxRedirects)
			}
			if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
				return errors.New("redirect to a non-HTTP URL")
			}
			return nil
		},
	}
	method := http.MethodGet
	if req.Head {
		method = http.MethodHead
	}
	hr, _ := http.NewRequestWithContext(ctx, method, req.URL.String(), nil)
	hr.Header.Set("User-Agent", "net-ro")
	resp, err := c.Do(hr)
	if err != nil {
		var nr *netRefusal
		if errors.As(err, &nr) {
			return nil, nr
		}
		return nil, err
	}
	defer resp.Body.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", resp.Proto, resp.Status)
	if usedTLS || resp.TLS != nil {
		b.WriteString(tlsNotVerified + "\n")
	} else {
		b.WriteString(plainHTTP + "\n")
	}
	if resp.Request != nil && resp.Request.URL.String() != req.URL.String() {
		fmt.Fprintf(&b, "# after redirects: %s\n", resp.Request.URL)
	}
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "Set-Cookie" {
			continue
		}
		for _, v := range resp.Header[k] {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	b.WriteString("\n")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, NetHTTPBodyCap+1))
	if len(body) > NetHTTPBodyCap {
		b.Write(body[:NetHTTPBodyCap])
		fmt.Fprintf(&b, "\n[body cut at %d bytes]\n", NetHTTPBodyCap)
	} else {
		b.Write(body)
	}
	return []byte(b.String()), nil
}

// Every http result says it is not authenticated.
const (
	tlsNotVerified = "# TLS not verified: the server's certificate was not checked, so this answer is not authenticated"
	plainHTTP      = "# plain HTTP: not encrypted, not authenticated"
)

func localPing(ctx context.Context, ip netip.Addr, count int) ([]byte, error) {
	out := &capped{max: NetOutputCap}
	cmd := exec.CommandContext(ctx, "ping", "-n", "-c", strconv.Itoa(count), "-W", "2", ip.String())
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		err = nil // no replies is a result; ping's summary says so
	}
	return out.bytes(), err
}

// stats are --repeat timings.
type stats struct {
	n, ok, errs int
	took        []time.Duration
	errMsgs     map[string]int
}

func (st *stats) add(d time.Duration, err error, ok bool) {
	st.n++
	st.took = append(st.took, d)
	if ok {
		st.ok++
	}
	if err != nil {
		st.errs++
		if st.errMsgs == nil {
			st.errMsgs = map[string]int{}
		}
		st.errMsgs[err.Error()]++
	}
}

func (st *stats) write(b *strings.Builder, asked int) {
	if st.n < asked {
		fmt.Fprintf(b, "stopped after %d of %d runs: the call's %s limit\n", st.n, asked, CallTimeout)
	}
	if st.n == 0 {
		return
	}
	t := slices.Clone(st.took)
	slices.Sort(t)
	var sum time.Duration
	for _, d := range t {
		sum += d
	}
	pct := func(p int) time.Duration { return t[(len(t)-1)*p/100] }
	fmt.Fprintf(b, "time ms: min %s p50 %s p95 %s max %s avg %s\n",
		ms(t[0]), ms(pct(50)), ms(pct(95)), ms(t[len(t)-1]), ms(sum/time.Duration(len(t))))
	msgs := make([]string, 0, len(st.errMsgs))
	for m := range st.errMsgs {
		msgs = append(msgs, m)
	}
	sort.Slice(msgs, func(i, j int) bool { return st.errMsgs[msgs[i]] > st.errMsgs[msgs[j]] })
	for i, m := range msgs {
		if i == 5 {
			break
		}
		fmt.Fprintf(b, "error x%d: %s\n", st.errMsgs[m], m)
	}
}

func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d.Microseconds())/1000, 'f', 1, 64)
}
