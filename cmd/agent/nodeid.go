package main

import (
	"fmt"
	"os"
	"strings"
)

// nodeID names this node within its cluster. The cluster comes from the
// driver (clusterIDFromDriver); the node is the hostname, which is what the
// operator sees in `cluster check` and in the fleet view.
//
// Folded, because the SaaS folds too: a node enrolling as "SKY142" is the node
// stored as "sky142", not a second one.
func nodeID(explicit string) (string, error) {
	if s := strings.TrimSpace(explicit); s != "" {
		return strings.ToLower(s), nil
	}
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("agent: no -node given and the hostname is unreadable: %w", err)
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", fmt.Errorf("agent: no -node given and the hostname is empty")
	}
	return host, nil
}
