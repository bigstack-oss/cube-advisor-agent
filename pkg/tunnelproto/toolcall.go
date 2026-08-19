package tunnelproto

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The tool-channel payload contract.
//
// This is here rather than in the agent's internal packages because it crosses
// a repository boundary: the agent writes these frames and the SaaS reads them.
// A wire type that only one side can import gets restated on the other, and
// then there are two definitions of one protocol — which is to say none.

// MaxToolArgsBytes bounds the argument frame. The receiving registry rejects
// unknown arguments anyway; this stops a peer making the agent buffer first.
const MaxToolArgsBytes = 8 << 10

// RefusedReason is the single reason string a refused call returns.
//
// Every refusal looks identical to the SaaS; the specific cause goes to the
// customer's local audit log, where it belongs. A precise refusal is a probe
// oracle — it would let a caller map the allowlist by reading error text.
const RefusedReason = "refused"

// ToolResult is the single frame an agent writes back on a tool channel.
//
// Success is explicit rather than inferred from the output, so the SaaS never
// has to parse tool output to find out whether the tool ran.
type ToolResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Refused builds the one refusal every rejected call returns.
func Refused() ToolResult { return ToolResult{OK: false, Error: RefusedReason} }

// WriteToolArgs writes the argument frame: one newline-terminated JSON object.
//
// Arguments are strings, not arbitrary JSON. A tool argument that reaches a
// cluster is validated against an exact-match allowlist, and a type the
// allowlist cannot express is one it cannot check.
func WriteToolArgs(w io.Writer, args map[string]string) error {
	if args == nil {
		args = map[string]string{}
	}
	line, err := json.Marshal(args)
	if err != nil {
		return err
	}
	if len(line)+1 > MaxToolArgsBytes {
		return fmt.Errorf("argument frame exceeds %d bytes", MaxToolArgsBytes)
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// ReadToolArgs reads the argument frame: exactly one newline-terminated JSON
// object, `{}` when the tool takes none.
//
// Line-framed rather than read-to-EOF, and the reason is concrete: a channel is
// a yamux stream, and yamux streams have no half-close. A caller cannot signal
// "I have finished sending arguments" without closing the stream it is about to
// read the result from, so reading to EOF here would deadlock every call. The
// framing matches the channel-open header for the same reason.
func ReadToolArgs(r io.Reader) (map[string]string, error) {
	br := bufio.NewReaderSize(r, MaxToolArgsBytes)
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("argument frame exceeds %d bytes", MaxToolArgsBytes)
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(line))) == 0 {
		return nil, nil
	}
	var args map[string]string
	if err := json.Unmarshal(line, &args); err != nil {
		return nil, err
	}
	return args, nil
}

// WriteToolResult writes the result frame.
func WriteToolResult(w io.Writer, r ToolResult) error {
	return json.NewEncoder(w).Encode(r)
}

// ReadToolResult reads the result frame.
//
// Bounded for the same reason the argument frame is: the SaaS is reading from a
// cluster it does not control, and an unbounded read is an unbounded
// allocation.
func ReadToolResult(r io.Reader) (ToolResult, error) {
	var out ToolResult
	dec := json.NewDecoder(io.LimitReader(r, MaxToolOutputBytes))
	if err := dec.Decode(&out); err != nil {
		return ToolResult{}, err
	}
	return out, nil
}

// MaxToolOutputBytes bounds a result frame. Generous next to `cluster check`
// output, small next to memory exhaustion from a hostile or broken peer.
const MaxToolOutputBytes = 1 << 20
