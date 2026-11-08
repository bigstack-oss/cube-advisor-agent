package main

import (
	"bufio"
	"os"
	"strings"
)

// cubesysPolicy holds this node's CubeCOS role; a var for tests.
var cubesysPolicy = "/etc/policies/cubesys/cubesys1_0.yml"

// nodeRole returns the node's cubesys role, or "" when there is none.
// Read the way hex_sdk's is_control_node reads it.
func nodeRole() string {
	f, err := os.Open(cubesysPolicy)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && k == "role" {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}
