// Package tunnel carries the wire protocol over a single outbound connection.
//
// One session multiplexes many channels — control, tool calls, and interactive
// consoles — so the agent opens exactly one connection outward and never needs
// an inbound rule. Multiplexing and per-channel flow control come from yamux:
// a console channel streaming `tail -f` has its own window and cannot starve a
// tool call sharing the connection.
//
// The session layer works over any net.Conn, which keeps the websocket out of
// the core and makes the protocol testable without a network. Both sides import
// this package so the framing has one implementation rather than two that must
// agree.
package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// handshakeTimeout bounds the control exchange at session open. An agent that
// connects and then says nothing must not hold a slot.
const handshakeTimeout = 30 * time.Second

// Session is one multiplexed tunnel.
type Session struct {
	mux *yamux.Session
	ctl net.Conn // the control stream, held open for the session's life
	ack tunnelproto.HelloAck
}

// Ack is the handshake result the peer returned (agent side) or produced
// (SaaS side).
func (s *Session) Ack() tunnelproto.HelloAck { return s.ack }

func muxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	// yamux's own keepalive is enough; the transport underneath may add its own.
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 30 * time.Second
	// Silence the library's logger — session lifecycle is logged by the caller,
	// which knows the cluster identity that makes a line actionable.
	c.LogOutput = nil
	c.Logger = discardLogger()
	return c
}

// Dial performs the agent side of session setup over an established conn: it
// becomes the multiplexing client, opens the control stream and sends Hello.
//
// A refusal is returned as an error carrying the SaaS's operator-readable
// reason, because the agent's log is where somebody will look first.
func Dial(ctx context.Context, conn net.Conn, hello tunnelproto.Hello) (*Session, error) {
	mux, err := yamux.Client(conn, muxConfig())
	if err != nil {
		return nil, fmt.Errorf("tunnel: mux client: %w", err)
	}
	ctl, err := mux.Open()
	if err != nil {
		mux.Close()
		return nil, fmt.Errorf("tunnel: open control stream: %w", err)
	}
	_ = ctl.SetDeadline(deadline(ctx))

	if err := json.NewEncoder(ctl).Encode(hello); err != nil {
		mux.Close()
		return nil, fmt.Errorf("tunnel: send hello: %w", err)
	}
	var ack tunnelproto.HelloAck
	if err := json.NewDecoder(ctl).Decode(&ack); err != nil {
		mux.Close()
		return nil, fmt.Errorf("tunnel: read hello ack: %w", err)
	}
	if !ack.Accepted {
		mux.Close()
		return nil, fmt.Errorf("tunnel: refused by the service: %s", ack.Reason)
	}
	_ = ctl.SetDeadline(time.Time{})
	return &Session{mux: mux, ctl: ctl, ack: ack}, nil
}

// Accept performs the SaaS side over an established conn: it becomes the
// multiplexing server, accepts the control stream and applies admit to the
// agent's Hello.
//
// A refused agent still receives its HelloAck before the session closes — the
// reason has to reach the operator, and a bare disconnect tells them nothing.
func Accept(ctx context.Context, conn net.Conn, admit func(tunnelproto.Hello) tunnelproto.HelloAck) (*Session, error) {
	mux, err := yamux.Server(conn, muxConfig())
	if err != nil {
		return nil, fmt.Errorf("tunnel: mux server: %w", err)
	}
	ctl, err := mux.Accept()
	if err != nil {
		mux.Close()
		return nil, fmt.Errorf("tunnel: accept control stream: %w", err)
	}
	_ = ctl.SetDeadline(deadline(ctx))

	var hello tunnelproto.Hello
	if err := json.NewDecoder(ctl).Decode(&hello); err != nil {
		mux.Close()
		return nil, fmt.Errorf("tunnel: read hello: %w", err)
	}
	ack := admit(hello)
	if err := json.NewEncoder(ctl).Encode(ack); err != nil {
		mux.Close()
		return nil, fmt.Errorf("tunnel: send hello ack: %w", err)
	}
	if !ack.Accepted {
		mux.Close()
		return nil, fmt.Errorf("tunnel: refused agent on %s: %s", hello.ClusterID, ack.Reason)
	}
	_ = ctl.SetDeadline(time.Time{})
	return &Session{mux: mux, ctl: ctl, ack: ack}, nil
}

// Channel is an accepted stream plus the request that opened it.
type Channel struct {
	net.Conn
	Open tunnelproto.ChannelOpen
}

// OpenChannel opens a new channel to a symbolic target.
//
// The request is validated before it is sent even though the peer validates on
// receipt; a caller should never knowingly emit something the peer will reject.
func (s *Session) OpenChannel(ctx context.Context, id uint32, kind tunnelproto.ChannelKind, target tunnelproto.Target) (net.Conn, error) {
	open := tunnelproto.ChannelOpen{ID: id, Kind: kind, Target: target}
	if err := open.Validate(); err != nil {
		return nil, fmt.Errorf("tunnel: refusing to open an invalid channel: %w", err)
	}
	stream, err := s.mux.Open()
	if err != nil {
		return nil, fmt.Errorf("tunnel: open stream: %w", err)
	}
	_ = stream.SetWriteDeadline(deadline(ctx))
	if err := json.NewEncoder(stream).Encode(open); err != nil {
		stream.Close()
		return nil, fmt.Errorf("tunnel: send channel open: %w", err)
	}
	_ = stream.SetWriteDeadline(time.Time{})
	return stream, nil
}

// AcceptChannel accepts the next channel and validates its open request.
//
// Validation here is not redundant with the sender's: the agent must never
// trust the SaaS, so an open naming an address — or crossing the plane
// boundary — is rejected on receipt regardless of what the sender checked.
func (s *Session) AcceptChannel(ctx context.Context) (*Channel, error) {
	stream, err := s.mux.Accept()
	if err != nil {
		return nil, err
	}
	_ = stream.SetReadDeadline(deadline(ctx))
	var open tunnelproto.ChannelOpen
	if err := json.NewDecoder(stream).Decode(&open); err != nil {
		stream.Close()
		return nil, fmt.Errorf("tunnel: read channel open: %w", err)
	}
	if err := open.Validate(); err != nil {
		stream.Close()
		return nil, fmt.Errorf("tunnel: rejecting channel open from peer: %w", err)
	}
	_ = stream.SetReadDeadline(time.Time{})
	return &Channel{Conn: stream, Open: open}, nil
}

// SendKillSwitch tells the peer to drop everything. The customer holds this
// control, so it takes effect on the peer's next read rather than waiting for
// anything in flight to finish.
func (s *Session) SendKillSwitch(k tunnelproto.KillSwitch) error {
	if err := json.NewEncoder(s.ctl).Encode(k); err != nil {
		return fmt.Errorf("tunnel: send kill switch: %w", err)
	}
	return nil
}

// AwaitKillSwitch blocks until the peer sends one.
func (s *Session) AwaitKillSwitch() (tunnelproto.KillSwitch, error) {
	var k tunnelproto.KillSwitch
	err := json.NewDecoder(s.ctl).Decode(&k)
	return k, err
}

// Close drops the session and every channel on it — including live console
// sessions, which is the point: a kill switch that waits politely is not one.
func (s *Session) Close() error { return s.mux.Close() }

// IsClosed reports whether the session has gone away.
func (s *Session) IsClosed() bool { return s.mux.IsClosed() }

func deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(handshakeTimeout)
}
