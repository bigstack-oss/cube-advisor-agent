package tunnel

import (
	"context"
	"net"
	"net/http"

	"github.com/coder/websocket"
)

// The websocket is deliberately thin here: it produces a net.Conn and the
// session layer does the rest. Keeping the transport swappable is what lets the
// protocol be tested over an in-memory pipe, and what would let a future
// deployment use something other than wss without touching the session code.

// DialWS opens an outbound websocket and returns it as a net.Conn.
//
// Outbound-only over 443 is the whole connectivity story: it traverses
// corporate egress proxies with no inbound rule and no VPN.
func DialWS(ctx context.Context, url string, hdr http.Header, tlsClient *http.Client) (net.Conn, error) {
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: hdr,
		HTTPClient: tlsClient,
	})
	if err != nil {
		return nil, err
	}
	// Binary frames: the session layer owns framing, the websocket just moves bytes.
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// AcceptWS upgrades an inbound request and returns it as a net.Conn.
func AcceptWS(w http.ResponseWriter, r *http.Request, opts *websocket.AcceptOptions) (net.Conn, error) {
	c, err := websocket.Accept(w, r, opts)
	if err != nil {
		return nil, err
	}
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}
