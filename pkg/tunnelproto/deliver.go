package tunnelproto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Package delivery: the Advisor pushes a firmware or fixpack file to a node
// over a tool channel, resuming a dropped transfer where the file stops.
//
//	SaaS  → args frame {kind, name, size, sha256}
//	agent → DeliverOffer (one JSON line); Offset is where to resume
//	SaaS  → the file's bytes from Offset to size, nothing else
//	agent → DeliverReport (one JSON line) after the checksum
//
// The channel must be opened Approved: a person approved the install.

// PackageReceiveTool is the tool channel a delivery opens.
const PackageReceiveTool = "package_receive"

// PackageReceiveCapability in Hello.Capabilities says the agent takes deliveries.
const PackageReceiveCapability = "package-receive"

// FreeSpaceFactor is the free space a delivery needs, as a multiple of the
// file's size (owner decision D1, still open).
const FreeSpaceFactor = 2

// MaxPackageBytes bounds one delivered file.
const MaxPackageBytes = int64(64) << 30

// Package kinds and where each lands on the node.
const (
	PackageFirmware = "firmware"
	PackageFixpack  = "fixpack"
)

// PackageDirs maps a kind to its directory on a CubeCOS node.
var PackageDirs = map[string]string{
	PackageFirmware: "/var/update",
	PackageFixpack:  "/var/fixpack",
}

// DeliverOffer answers a delivery request before any bytes move.
type DeliverOffer struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Offset is how much of the file the node already holds.
	Offset int64 `json:"offset"`
	// Complete: the file is already there and checked; send nothing.
	Complete  bool   `json:"complete,omitempty"`
	FreeBytes int64  `json:"freeBytes"`
	NeedBytes int64  `json:"needBytes"`
	Path      string `json:"path,omitempty"`
}

// Checksum states in a DeliverReport.
const (
	ChecksumOK       = "ok"
	ChecksumMismatch = "mismatch"
)

// DeliverReport ends a delivery.
type DeliverReport struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Path     string `json:"path,omitempty"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256,omitempty"`
	Checksum string `json:"checksum,omitempty"`
}

// DeliverRequest is a delivery's argument frame, parsed.
type DeliverRequest struct {
	Kind   string
	Name   string
	Size   int64
	SHA256 string
}

var (
	packageNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	sha256Re      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Args renders the request as the argument frame.
func (r DeliverRequest) Args() map[string]string {
	return map[string]string{"kind": r.Kind, "name": r.Name,
		"size": strconv.FormatInt(r.Size, 10), "sha256": r.SHA256}
}

// ParseDeliverRequest validates an argument frame.
func ParseDeliverRequest(args map[string]string) (DeliverRequest, error) {
	for k := range args {
		switch k {
		case "kind", "name", "size", "sha256":
		default:
			return DeliverRequest{}, fmt.Errorf("unknown argument %q", k)
		}
	}
	r := DeliverRequest{Kind: args["kind"], Name: args["name"], SHA256: args["sha256"]}
	if _, ok := PackageDirs[r.Kind]; !ok {
		return r, fmt.Errorf("kind %q is not firmware or fixpack", r.Kind)
	}
	if !packageNameRe.MatchString(r.Name) || strings.Contains(r.Name, "..") {
		return r, fmt.Errorf("name %q is not a plain file name", r.Name)
	}
	size, err := strconv.ParseInt(args["size"], 10, 64)
	if err != nil || size <= 0 || size > MaxPackageBytes {
		return r, fmt.Errorf("size %q is not between 1 and %d", args["size"], MaxPackageBytes)
	}
	r.Size = size
	if !sha256Re.MatchString(r.SHA256) {
		return r, fmt.Errorf("sha256 must be 64 lowercase hex digits")
	}
	return r, nil
}

// SendPackage is the SaaS side of a delivery on an open package_receive
// channel. open returns the file's bytes from offset; sent is told after
// each write how many bytes of the file the node now has. A nil error with
// a refused offer or a failed report means the node said no.
func SendPackage(conn io.ReadWriter, req DeliverRequest, open func(offset int64) (io.Reader, error),
	sent func(have int64)) (DeliverOffer, DeliverReport, error) {
	if err := WriteToolArgs(conn, req.Args()); err != nil {
		return DeliverOffer{}, DeliverReport{}, err
	}
	br := bufio.NewReader(conn)
	var offer DeliverOffer
	if err := readLine(br, &offer); err != nil {
		return offer, DeliverReport{}, fmt.Errorf("reading the node's offer: %w", err)
	}
	if !offer.OK {
		return offer, DeliverReport{Error: offer.Error}, nil
	}
	if !offer.Complete {
		if offer.Offset < 0 || offer.Offset > req.Size {
			return offer, DeliverReport{}, fmt.Errorf("the node offered to resume at %d of %d bytes", offer.Offset, req.Size)
		}
		src, err := open(offer.Offset)
		if err != nil {
			return offer, DeliverReport{}, err
		}
		have := offer.Offset
		buf := make([]byte, 1<<20)
		for have < req.Size {
			n, rerr := src.Read(buf[:min(int64(len(buf)), req.Size-have)])
			if n > 0 {
				if _, err := conn.Write(buf[:n]); err != nil {
					return offer, DeliverReport{}, fmt.Errorf("sending at %d of %d bytes: %w", have, req.Size, err)
				}
				have += int64(n)
				if sent != nil {
					sent(have)
				}
			}
			if rerr == io.EOF && have < req.Size {
				return offer, DeliverReport{}, fmt.Errorf("the source ended at %d of %d bytes", have, req.Size)
			}
			if rerr != nil && rerr != io.EOF {
				return offer, DeliverReport{}, rerr
			}
		}
	}
	var rep DeliverReport
	if err := readLine(br, &rep); err != nil {
		return offer, rep, fmt.Errorf("reading the node's report: %w", err)
	}
	return offer, rep, nil
}

func readLine(br *bufio.Reader, v any) error {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return err
	}
	if len(line) > MaxToolOutputBytes {
		return fmt.Errorf("line exceeds %d bytes", MaxToolOutputBytes)
	}
	return json.Unmarshal(line, v)
}
