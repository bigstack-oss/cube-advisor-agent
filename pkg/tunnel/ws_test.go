package tunnel_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// The websocket framing carries a whole session: Hello over the control
// stream, then a tool channel round trip. TLS is not in play here — the mTLS
// admission path is pinned by the SaaS repository's e2e suite; this test pins
// that the ws transport is a faithful net.Conn for the session layer.
func TestSessionOverWebsocket(t *testing.T) {
	served := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tunnel.WSPath {
			http.NotFound(w, r)
			return
		}
		conn, err := tunnel.AcceptWS(w, r, nil)
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		sess, err := tunnel.Accept(r.Context(), conn, func(h tunnelproto.Hello) tunnelproto.HelloAck {
			return tunnelproto.HelloAck{Accepted: true}
		})
		if err != nil {
			served <- err
			return
		}
		defer sess.Close()
		ch, err := sess.AcceptChannel(context.Background())
		if err != nil {
			served <- err
			return
		}
		defer ch.Close()
		if _, err := tunnelproto.ReadToolArgs(ch); err != nil {
			served <- err
			return
		}
		served <- tunnelproto.WriteToolResult(ch, tunnelproto.ToolResult{OK: true, Output: "pong"})
	}))
	defer srv.Close()

	ctx := context.Background()
	conn, err := tunnel.DialWS(ctx, "ws"+srv.URL[len("http"):]+tunnel.WSPath, nil, srv.Client())
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	sess, err := tunnel.Dial(ctx, conn, tunnelproto.Hello{
		ClusterID: "c1", Fingerprint: "fp", ProtocolVersion: tunnelproto.Version,
	})
	if err != nil {
		t.Fatalf("session dial: %v", err)
	}
	defer sess.Close()

	ch, err := sess.OpenChannel(ctx, 1, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: "cluster_check"})
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer ch.Close()
	if err := tunnelproto.WriteToolArgs(ch, map[string]string{}); err != nil {
		t.Fatalf("write args: %v", err)
	}
	res, err := tunnelproto.ReadToolResult(ch)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !res.OK || res.Output != "pong" {
		t.Errorf("result = %+v, want ok pong", res)
	}
	if err := <-served; err != nil {
		t.Errorf("server side: %v", err)
	}
}
