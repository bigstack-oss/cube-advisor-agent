package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// MgrPortOwner is the device owner CubeCOS gives the port it keeps on every
// network that has VMs (sdk_os.sh, OS_MGR_PORT_OWNER).
const MgrPortOwner = "network:floatingip_agent_gateway"

// ErrNoRelay is returned when no leg on the target's network can be found.
var ErrNoRelay = errors.New("console: no relay to this web target")

// directTimeout bounds the direct attempt when a relay can follow it.
const directTimeout = 3 * time.Second

// planTTL is how long a relay route is reused before it is looked up again.
const planTTL = time.Minute

var (
	uuidRe      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	relayHostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

// relaySSHArgs match the node's own ssh_config for root, as peer reads do.
var relaySSHArgs = []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
	"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
	"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
	"-o", "ControlPath=none", "-o", "LogLevel=ERROR"}

// Neutron is the admin OpenStack client the relay reads the network API with.
type Neutron interface {
	Endpoint(ctx context.Context, service string) (endpoint, token string, err error)
	HTTP() *http.Client
}

// RelayPlan is one route through a mgr namespace.
type RelayPlan struct {
	Node  string // node holding the namespace
	Netns string // mgr-<first 8 of the network id>
	IP    string // address on that network
	Port  string
}

// Argv is the command that pipes stdin/stdout to the target. local runs it on
// this node; otherwise it goes over the cluster's node-to-node SSH. Every
// element is validated by Plan, so none can be read as an option or by a shell.
func (p RelayPlan) Argv(local bool) []string {
	cmd := []string{"ip", "netns", "exec", p.Netns, "socat", "-", "TCP4:" + p.IP + ":" + p.Port + ",connect-timeout=5"}
	if local {
		return cmd
	}
	argv := append([]string{"ssh"}, relaySSHArgs...)
	return append(append(argv, "root@"+p.Node), cmd...)
}

// NetnsRelay reaches an address the node cannot route to, through the leg
// CubeCOS keeps on that address's network.
type NetnsRelay struct {
	OpenStack Neutron
	// Hostname is this node's name in the cluster's node list.
	Hostname string
	// Audit records each relayed open. Nil records nothing.
	Audit func(target string, p RelayPlan, err error)

	// start runs argv and returns its stdio as a connection; nil uses exec.
	start func(argv []string) (net.Conn, error)

	mu    sync.Mutex
	plans map[string]cachedPlan
}

type cachedPlan struct {
	p     RelayPlan
	until time.Time
}

// Plan finds the route to hostport: the fixed address behind a floating IP,
// its network, and the node whose mgr namespace has a leg there.
func (r *NetnsRelay) Plan(ctx context.Context, hostport string) (RelayPlan, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return RelayPlan{}, err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return RelayPlan{}, fmt.Errorf("%w: %s is not a routable IPv4 address", ErrNoRelay, host)
	}
	if _, err := net.LookupPort("tcp", port); err != nil || strings.Trim(port, "0123456789") != "" {
		return RelayPlan{}, fmt.Errorf("%w: bad port %q", ErrNoRelay, port)
	}
	fixed, netID, err := r.locate(ctx, ip.String())
	if err != nil {
		return RelayPlan{}, err
	}
	var legs struct {
		Ports []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Host   string `json:"binding:host_id"`
		} `json:"ports"`
	}
	q := url.Values{"network_id": {netID}, "device_owner": {MgrPortOwner}}
	if err := r.get(ctx, "/v2.0/ports?"+q.Encode(), &legs); err != nil {
		return RelayPlan{}, err
	}
	for _, l := range legs.Ports {
		if !strings.HasSuffix(l.Name, "-"+netID) || l.Status != "ACTIVE" || !relayHostRe.MatchString(l.Host) {
			continue
		}
		return RelayPlan{Node: l.Host, Netns: "mgr-" + netID[:8], IP: fixed, Port: port}, nil
	}
	return RelayPlan{}, fmt.Errorf("%w: CubeCOS keeps no leg on network %s", ErrNoRelay, netID)
}

// locate returns the fixed address ip stands for and the network it is on.
func (r *NetnsRelay) locate(ctx context.Context, ip string) (fixed, netID string, err error) {
	var fips struct {
		FloatingIPs []struct {
			Fixed  string `json:"fixed_ip_address"`
			PortID string `json:"port_id"`
		} `json:"floatingips"`
	}
	if err := r.get(ctx, "/v2.0/floatingips?"+url.Values{"floating_ip_address": {ip}}.Encode(), &fips); err != nil {
		return "", "", err
	}
	if len(fips.FloatingIPs) == 1 && fips.FloatingIPs[0].PortID != "" {
		f := fips.FloatingIPs[0]
		var one struct {
			Port struct {
				NetworkID string `json:"network_id"`
			} `json:"port"`
		}
		if !uuidRe.MatchString(f.PortID) {
			return "", "", fmt.Errorf("%w: bad port id", ErrNoRelay)
		}
		if err := r.get(ctx, "/v2.0/ports/"+f.PortID, &one); err != nil {
			return "", "", err
		}
		fixed, netID = f.Fixed, one.Port.NetworkID
	} else {
		// Not a floating IP: a fixed address, which must name one port only.
		// Tenant networks reuse CIDRs, and a guess could reach another tenant.
		var ports struct {
			Ports []struct {
				NetworkID string `json:"network_id"`
			} `json:"ports"`
		}
		if err := r.get(ctx, "/v2.0/ports?"+url.Values{"fixed_ips": {"ip_address=" + ip}}.Encode(), &ports); err != nil {
			return "", "", err
		}
		if len(ports.Ports) != 1 {
			return "", "", fmt.Errorf("%w: %s names %d ports", ErrNoRelay, ip, len(ports.Ports))
		}
		fixed, netID = ip, ports.Ports[0].NetworkID
	}
	if p := net.ParseIP(fixed); p == nil || p.To4() == nil || !uuidRe.MatchString(netID) {
		return "", "", fmt.Errorf("%w: unusable address or network for %s", ErrNoRelay, ip)
	}
	return net.ParseIP(fixed).To4().String(), netID, nil
}

func (r *NetnsRelay) get(ctx context.Context, path string, into any) error {
	if r.OpenStack == nil {
		return fmt.Errorf("%w: no OpenStack credential on this node", ErrNoRelay)
	}
	endpoint, token, err := r.OpenStack.Endpoint(ctx, "network")
	if err != nil {
		return fmt.Errorf("console: relay lookup: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(endpoint, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", token)
	resp, err := r.OpenStack.HTTP().Do(req)
	if err != nil {
		return fmt.Errorf("console: relay lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("console: relay lookup: HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(into)
}

// Dial opens hostport through its relay. ctx bounds the lookup only: the
// relay process lives until the connection is closed.
func (r *NetnsRelay) Dial(ctx context.Context, hostport string) (net.Conn, error) {
	p, err := r.plan(ctx, hostport)
	var conn net.Conn
	if err == nil {
		start := r.start
		if start == nil {
			start = startProc
		}
		conn, err = start(p.Argv(strings.EqualFold(p.Node, r.Hostname)))
	}
	if r.Audit != nil {
		r.Audit(hostport, p, err)
	}
	return conn, err
}

func (r *NetnsRelay) plan(ctx context.Context, hostport string) (RelayPlan, error) {
	r.mu.Lock()
	c, ok := r.plans[hostport]
	r.mu.Unlock()
	if ok && time.Now().Before(c.until) {
		return c.p, nil
	}
	p, err := r.Plan(ctx, hostport)
	if err != nil {
		return RelayPlan{}, err
	}
	r.mu.Lock()
	if r.plans == nil {
		r.plans = map[string]cachedPlan{}
	}
	r.plans[hostport] = cachedPlan{p, time.Now().Add(planTTL)}
	r.mu.Unlock()
	return p, nil
}

// FallbackDialer dials directly, and through relay when this node has no
// route to the address. A refused connection is an answer, not a missing
// route, and is returned as it is.
func FallbackDialer(direct Dialer, relay *NetnsRelay) Dialer {
	if direct == nil {
		direct = defaultDialer
	}
	var mu sync.Mutex
	viaRelay := map[string]time.Time{}
	return func(ctx context.Context, address string) (net.Conn, error) {
		mu.Lock()
		skip := time.Now().Before(viaRelay[address])
		mu.Unlock()
		if !skip {
			dctx, cancel := context.WithTimeout(ctx, directTimeout)
			conn, err := direct(dctx, address)
			cancel()
			if err == nil || !noRoute(err) {
				return conn, err
			}
		}
		conn, err := relay.Dial(ctx, address)
		mu.Lock()
		if err == nil {
			viaRelay[address] = time.Now().Add(planTTL)
		} else {
			delete(viaRelay, address)
		}
		mu.Unlock()
		return conn, err
	}
}

// noRoute reports whether err means the address could not be reached at all.
func noRoute(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// startProc runs argv with its stdio as the connection.
func startProc(argv []string) (net.Conn, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	c := &procConn{cmd: cmd, in: in, out: out}
	cmd.Stderr = &c.errOut
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("console: start the relay: %w", err)
	}
	return c, nil
}

// procConn is a relay process seen as a connection. Closing it ends the process.
type procConn struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    io.ReadCloser
	errOut tail
	once   sync.Once
}

func (c *procConn) Read(p []byte) (int, error) {
	n, err := c.out.Read(p)
	if err != nil && n == 0 {
		if msg := c.errOut.String(); msg != "" {
			return 0, fmt.Errorf("console: relay ended: %s", msg)
		}
	}
	return n, err
}

func (c *procConn) Write(p []byte) (int, error) { return c.in.Write(p) }

func (c *procConn) Close() error {
	c.once.Do(func() {
		_ = c.in.Close()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		go func() { _ = c.cmd.Wait() }()
	})
	return nil
}

func (c *procConn) LocalAddr() net.Addr              { return relayAddr{} }
func (c *procConn) RemoteAddr() net.Addr             { return relayAddr{} }
func (c *procConn) SetDeadline(time.Time) error      { return nil }
func (c *procConn) SetReadDeadline(time.Time) error  { return nil }
func (c *procConn) SetWriteDeadline(time.Time) error { return nil }

type relayAddr struct{}

func (relayAddr) Network() string { return "relay" }
func (relayAddr) String() string  { return "relay" }

// tail keeps the first few hundred bytes of the relay's stderr.
type tail struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if room := 512 - t.buf.Len(); room > 0 {
		t.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(t.buf.String())
}
