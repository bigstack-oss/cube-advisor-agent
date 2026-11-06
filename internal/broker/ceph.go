package broker

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CephCommand is one entry of Ceph's own command table.
type CephCommand struct {
	// Sig holds each position's literal word, or "" for a parameter.
	Sig []string
	// Rest is true when the last parameter takes any number of words.
	Rest bool
	Perm string
}

// ParseCephDescriptions reads get_command_descriptions output (the monitor's
// or manager's) into commands.
func ParseCephDescriptions(raw []byte) ([]CephCommand, error) {
	var d map[string]struct {
		Sig  []json.RawMessage `json:"sig"`
		Perm string            `json:"perm"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("ceph command descriptions: %w", err)
	}
	var out []CephCommand
	for _, c := range d {
		cmd := CephCommand{Perm: c.Perm}
		for _, s := range c.Sig {
			var word string
			if json.Unmarshal(s, &word) == nil {
				cmd.Sig = append(cmd.Sig, word)
				continue
			}
			var p struct {
				N any `json:"n"`
			}
			_ = json.Unmarshal(s, &p)
			cmd.Sig = append(cmd.Sig, "")
			if p.N == "N" {
				cmd.Rest = true
			}
		}
		out = append(out, cmd)
	}
	return out, nil
}

// pgReads is the named exception (ADR 0019): the OSD command table carries no
// permission markings, so these two per-PG reads are listed here.
var pgReads = map[string]bool{"query": true, "list_unfound": true}

var formats = map[string]bool{"json": true, "json-pretty": true, "plain": true}

// CheckCephArgs decides whether args (the words after "ceph") may run. The
// commands whose literal words fit args best decide: all must be marked
// exactly "r" in Ceph's table. Only output-format flags are accepted.
func CheckCephArgs(table []CephCommand, args []string) error {
	words, err := stripFormat(args)
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return fmt.Errorf("no command")
	}
	if words[0] == "pg" && len(words) >= 3 && pgReads[words[2]] && (len(words) == 3 || words[2] == "list_unfound" && len(words) == 4) {
		return nil
	}
	best, bestScore := []CephCommand(nil), 0
	for _, c := range table {
		if s := fit(c, words); s > bestScore {
			best, bestScore = []CephCommand{c}, s
		} else if s > 0 && s == bestScore {
			best = append(best, c)
		}
	}
	if len(best) == 0 {
		return fmt.Errorf("%q is not a command in Ceph's command table", strings.Join(words, " "))
	}
	for _, c := range best {
		if c.Perm != "r" {
			return fmt.Errorf("%q is marked %q in Ceph's command table, not read-only", strings.Join(words, " "), c.Perm)
		}
	}
	return nil
}

// fit scores how many literal words of c match words at their positions; 0
// when any literal mismatches or words don't fit the signature's length.
func fit(c CephCommand, words []string) int {
	if len(words) > len(c.Sig) && !c.Rest {
		return 0
	}
	score := 0
	for i, lit := range c.Sig {
		if i >= len(words) {
			if lit != "" {
				return 0
			}
			continue
		}
		if lit == "" {
			continue
		}
		if words[i] != lit {
			return 0
		}
		score++
	}
	return score
}

func stripFormat(args []string) ([]string, error) {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || a == "--format":
			if i+1 >= len(args) || !formats[args[i+1]] {
				return nil, fmt.Errorf("%s takes json, json-pretty or plain", a)
			}
			i++
		case strings.HasPrefix(a, "--format="):
			if !formats[strings.TrimPrefix(a, "--format=")] {
				return nil, fmt.Errorf("%s: format must be json, json-pretty or plain", a)
			}
		case strings.HasPrefix(a, "-"):
			return nil, fmt.Errorf("option %q is not accepted; only -f/--format", a)
		default:
			out = append(out, a)
		}
	}
	return out, nil
}
