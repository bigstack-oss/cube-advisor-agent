package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// receiveHarness serves a Receiver writing under a temp dir with free bytes free.
func receiveHarness(t *testing.T, free int64) (*tunnel.Session, string, *recorder) {
	t.Helper()
	rec := &recorder{}
	reg, err := toolplane.New(toolplane.Tools, rec)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a, b := connPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	saasCh := make(chan *tunnel.Session, 1)
	go func() {
		s, _ := tunnel.Accept(ctx, b, tunnelproto.Negotiate)
		saasCh <- s
	}()
	agentSess, err := tunnel.Dial(ctx, a, tunnelproto.Hello{ClusterID: "c1", Fingerprint: "fp",
		ProtocolVersion: tunnelproto.Version})
	if err != nil {
		t.Fatal(err)
	}
	saas := <-saasCh
	srv := &Server{Tools: reg, Receive: &Receiver{
		Dirs:  map[string]string{tunnelproto.PackageFirmware: filepath.Join(dir, "update")},
		Free:  func(string) (int64, error) { return free, nil },
		Idle:  2 * time.Second,
		Audit: rec,
	}}
	go func() { _ = srv.Serve(ctx, agentSess) }()
	t.Cleanup(func() { agentSess.Close(); saas.Close() })
	return saas, filepath.Join(dir, "update"), rec
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func deliver(t *testing.T, saas *tunnel.Session, req tunnelproto.DeliverRequest, data []byte, approved bool) (tunnelproto.DeliverOffer, tunnelproto.DeliverReport, error) {
	t.Helper()
	var opts []tunnel.OpenOption
	if approved {
		opts = append(opts, tunnel.ApprovedByPerson())
	}
	conn, err := saas.OpenChannel(context.Background(), 7, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: tunnelproto.PackageReceiveTool}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return tunnelproto.SendPackage(conn, req, func(off int64) (io.Reader, error) {
		return bytes.NewReader(data[off:]), nil
	}, nil)
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func TestADeliveryLandsChecked(t *testing.T) {
	saas, dir, rec := receiveHarness(t, 1<<30)
	data := payload(3<<20 + 5)
	req := tunnelproto.DeliverRequest{Kind: "firmware", Name: "CUBE_3.2.0.pkg", Size: int64(len(data)), SHA256: sum(data)}
	offer, rep, err := deliver(t, saas, req, data, true)
	if err != nil || !offer.OK || offer.Offset != 0 || !rep.OK || rep.Checksum != tunnelproto.ChecksumOK {
		t.Fatalf("offer %+v report %+v err %v", offer, rep, err)
	}
	if offer.NeedBytes != 2*req.Size || offer.FreeBytes != 1<<30 {
		t.Errorf("offer numbers = %+v", offer)
	}
	got, err := os.ReadFile(filepath.Join(dir, req.Name))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("landed file differs: %v", err)
	}
	if _, err := os.Stat(partPath(dir, req.Name)); !os.IsNotExist(err) {
		t.Errorf("the part file was left behind: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	calls := rec.snapshot()
	if len(calls) != 1 || !calls[0].Allowed || calls[0].Tool != tunnelproto.PackageReceiveTool {
		t.Errorf("audit = %+v", calls)
	}

	// Again: the file is there, so nothing is sent.
	offer, rep, err = deliver(t, saas, req, nil, true)
	if err != nil || !offer.Complete || !rep.OK {
		t.Fatalf("second delivery: offer %+v report %+v err %v", offer, rep, err)
	}
}

func TestADroppedDeliveryResumes(t *testing.T) {
	saas, dir, rec := receiveHarness(t, 1<<30)
	data := payload(4 << 20)
	req := tunnelproto.DeliverRequest{Kind: "firmware", Name: "p.pkg", Size: int64(len(data)), SHA256: sum(data)}

	// The link drops after 1.5 MiB.
	conn, err := saas.OpenChannel(context.Background(), 9, tunnelproto.ChannelTool,
		tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: tunnelproto.PackageReceiveTool}, tunnel.ApprovedByPerson())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cut := 3 << 19
	_, _, err = tunnelproto.SendPackage(conn, req, func(off int64) (io.Reader, error) {
		return io.MultiReader(bytes.NewReader(data[off:cut]), errReader{}), nil
	}, nil)
	conn.Close()
	if err == nil {
		t.Fatal("a cut source reported success")
	}
	part := partPath(dir, req.Name)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := os.Stat(part)
		if err == nil && st.Size() == int64(cut) && len(rec.snapshot()) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("part file after the drop: %v %v", st, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	offer, rep, err := deliver(t, saas, req, data, true)
	if err != nil || offer.Offset != int64(cut) || !rep.OK {
		t.Fatalf("resume: offer %+v report %+v err %v", offer, rep, err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, req.Name))
	if !bytes.Equal(got, data) {
		t.Fatal("the resumed file differs")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestADeliveryRefusals(t *testing.T) {
	data := payload(1 << 20)
	good := tunnelproto.DeliverRequest{Kind: "firmware", Name: "p.pkg", Size: int64(len(data)), SHA256: sum(data)}

	t.Run("not approved", func(t *testing.T) {
		saas, _, _ := receiveHarness(t, 1<<30)
		conn, err := saas.OpenChannel(context.Background(), 3, tunnelproto.ChannelTool,
			tunnelproto.Target{Kind: tunnelproto.TargetTool, Name: tunnelproto.PackageReceiveTool})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = tunnelproto.WriteToolArgs(conn, good.Args())
		var res tunnelproto.ToolResult
		if err := json.NewDecoder(conn).Decode(&res); err != nil || res.OK || res.Error != tunnelproto.RefusedReason {
			t.Fatalf("unapproved delivery = %+v, %v", res, err)
		}
	})
	t.Run("short of twice the size", func(t *testing.T) {
		saas, _, _ := receiveHarness(t, int64(len(data))*2-1)
		offer, _, err := deliver(t, saas, good, data, true)
		if err != nil || offer.OK || offer.NeedBytes != 2*good.Size || offer.FreeBytes != 2*good.Size-1 ||
			!strings.Contains(offer.Error, "2×") {
			t.Fatalf("offer = %+v, %v", offer, err)
		}
	})
	t.Run("a path in the name", func(t *testing.T) {
		saas, _, _ := receiveHarness(t, 1<<30)
		bad := good
		bad.Name = "../etc/passwd"
		offer, _, err := deliver(t, saas, bad, data, true)
		if err != nil || offer.OK {
			t.Fatalf("offer = %+v, %v", offer, err)
		}
	})
	t.Run("a kind the node does not take", func(t *testing.T) {
		saas, _, _ := receiveHarness(t, 1<<30)
		bad := good
		bad.Kind = "fixpack"
		offer, _, err := deliver(t, saas, bad, data, true)
		if err != nil || offer.OK {
			t.Fatalf("offer = %+v, %v", offer, err)
		}
	})
	t.Run("checksum mismatch", func(t *testing.T) {
		saas, dir, _ := receiveHarness(t, 1<<30)
		bad := good
		bad.SHA256 = strings.Repeat("0", 64)
		offer, rep, err := deliver(t, saas, bad, data, true)
		if err != nil || !offer.OK || rep.OK || rep.Checksum != tunnelproto.ChecksumMismatch || rep.SHA256 != good.SHA256 {
			t.Fatalf("offer %+v report %+v err %v", offer, rep, err)
		}
		if _, err := os.Stat(partPath(dir, good.Name)); !os.IsNotExist(err) {
			t.Error("a mismatched file was kept")
		}
		if _, err := os.Stat(filepath.Join(dir, good.Name)); !os.IsNotExist(err) {
			t.Error("a mismatched file was installed")
		}
	})
}
