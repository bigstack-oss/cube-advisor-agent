package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnel"
	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// Receiver writes delivered packages into their kind's directory.
type Receiver struct {
	// Dirs maps a kind to its directory; nil uses tunnelproto.PackageDirs.
	Dirs map[string]string
	// Free reports a directory's free bytes; nil uses statfs.
	Free func(dir string) (int64, error)
	// Idle ends a transfer that sends nothing for this long; zero is 2 min.
	Idle  time.Duration
	Audit toolplane.Auditor

	mu     sync.Mutex
	active map[string]bool
}

// claim marks path as receiving; false when another delivery has it.
func (r *Receiver) claim(path string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active[path] {
		return false
	}
	if r.active == nil {
		r.active = map[string]bool{}
	}
	r.active[path] = true
	return true
}

func (r *Receiver) release(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.active, path)
}

const defaultReceiveIdle = 2 * time.Minute

func (r *Receiver) dir(kind string) string {
	if r.Dirs != nil {
		return r.Dirs[kind]
	}
	return tunnelproto.PackageDirs[kind]
}

// partPath is where a transfer in progress is written.
func partPath(dir, name string) string { return filepath.Join(dir, "."+name+".advisor-part") }

func statfsFree(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// serveReceive runs one delivery on ch.
func (s *Server) serveReceive(ctx context.Context, ch *tunnel.Channel) {
	r := s.Receive
	if r == nil || !ch.Open.Approved {
		log.Printf("agent: %s refused (receiver %v, approved %v)", tunnelproto.PackageReceiveTool, r != nil, ch.Open.Approved)
		_ = writeResult(ch, tunnelproto.Refused())
		return
	}
	args, err := readArgs(ch)
	if err != nil {
		_ = writeResult(ch, tunnelproto.Refused())
		return
	}
	req, err := tunnelproto.ParseDeliverRequest(args)
	if err != nil {
		r.audit(args, false, err.Error(), 0)
		writeLine(ch, tunnelproto.DeliverOffer{Error: err.Error()})
		return
	}
	start := time.Now()
	rep := r.receive(ctx, ch, req)
	reason := rep.Error
	if rep.OK {
		reason = "delivered " + rep.Path
	}
	r.audit(args, rep.OK, reason, time.Since(start))
	writeLine(ch, rep)
}

func (r *Receiver) audit(args map[string]string, ok bool, reason string, d time.Duration) {
	if r.Audit != nil {
		r.Audit.RecordToolCall(toolplane.ToolCall{At: time.Now().UTC(), Tool: tunnelproto.PackageReceiveTool,
			Args: args, Allowed: ok, Reason: reason, Duration: d})
	}
}

// receive offers, takes the bytes and checks them. An offer that refuses is
// written here and returned as the report too.
func (r *Receiver) receive(ctx context.Context, ch *tunnel.Channel, req tunnelproto.DeliverRequest) tunnelproto.DeliverReport {
	dir := r.dir(req.Kind)
	fail := func(offer bool, format string, a ...any) tunnelproto.DeliverReport {
		msg := fmt.Sprintf(format, a...)
		if offer {
			writeLine(ch, tunnelproto.DeliverOffer{Error: msg})
		}
		return tunnelproto.DeliverReport{Error: msg}
	}
	if dir == "" {
		return fail(true, "this node takes no %s packages", req.Kind)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail(true, "%s: %v", dir, err)
	}
	dest, part := filepath.Join(dir, req.Name), partPath(dir, req.Name)
	if !r.claim(dest) {
		return fail(true, "%s is already being delivered", dest)
	}
	defer r.release(dest)

	// Already there: check it rather than send it again.
	if st, err := os.Stat(dest); err == nil {
		if st.Size() != req.Size {
			return fail(true, "%s already exists with a different size", dest)
		}
		sum, err := fileSum(dest)
		if err != nil || sum != req.SHA256 {
			return fail(true, "%s already exists with different content", dest)
		}
		writeLine(ch, tunnelproto.DeliverOffer{OK: true, Offset: req.Size, Complete: true, Path: dest})
		return tunnelproto.DeliverReport{OK: true, Path: dest, Size: req.Size, SHA256: sum, Checksum: tunnelproto.ChecksumOK}
	}

	var have int64
	if st, err := os.Stat(part); err == nil {
		have = st.Size()
		if have > req.Size {
			_ = os.Remove(part)
			have = 0
		}
	}
	freeFn := r.Free
	if freeFn == nil {
		freeFn = statfsFree
	}
	free, err := freeFn(dir)
	if err != nil {
		return fail(true, "free space of %s: %v", dir, err)
	}
	need := tunnelproto.FreeSpaceFactor * req.Size
	if free+have < need {
		msg := fmt.Sprintf("%s has %d bytes free; the package needs %d× its size, %d bytes", dir, free+have,
			tunnelproto.FreeSpaceFactor, need)
		writeLine(ch, tunnelproto.DeliverOffer{Error: msg, FreeBytes: free, NeedBytes: need})
		return tunnelproto.DeliverReport{Error: msg}
	}
	writeLine(ch, tunnelproto.DeliverOffer{OK: true, Offset: have, FreeBytes: free, NeedBytes: need, Path: dest})

	f, err := os.OpenFile(part, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return fail(false, "open %s: %v", part, err)
	}
	idle := r.Idle
	if idle <= 0 {
		idle = defaultReceiveIdle
	}
	n, cerr := io.CopyN(f, &idleReader{c: ch, idle: idle}, req.Size-have)
	serr := f.Sync()
	if err := f.Close(); serr == nil {
		serr = err
	}
	if cerr != nil {
		return fail(false, "transfer stopped at %d of %d bytes: %v", have+n, req.Size, cerr)
	}
	if serr != nil {
		return fail(false, "write %s: %v", part, serr)
	}
	sum, err := fileSum(part)
	if err != nil {
		return fail(false, "checksum %s: %v", part, err)
	}
	if sum != req.SHA256 {
		_ = os.Remove(part)
		return tunnelproto.DeliverReport{Error: "the file's sha256 does not match; it was removed", Size: req.Size,
			SHA256: sum, Checksum: tunnelproto.ChecksumMismatch}
	}
	if err := os.Rename(part, dest); err != nil {
		return fail(false, "rename %s: %v", part, err)
	}
	return tunnelproto.DeliverReport{OK: true, Path: dest, Size: req.Size, SHA256: sum, Checksum: tunnelproto.ChecksumOK}
}

// idleReader ends a read that waits longer than idle.
type idleReader struct {
	c    net.Conn
	idle time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	_ = r.c.SetReadDeadline(time.Now().Add(r.idle))
	n, err := r.c.Read(p)
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		err = fmt.Errorf("nothing arrived for %s", r.idle)
	}
	return n, err
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReaderSize(f, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeLine(w io.Writer, v any) {
	_ = json.NewEncoder(w).Encode(v)
}
