package main

import (
	"os"
	"strings"
	"testing"
)

func TestNodeIDPrefersTheFlagThenTheHostname(t *testing.T) {
	got, err := nodeID("SKY142")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sky142" {
		t.Errorf("nodeID(explicit) = %q, want it folded to sky142", got)
	}

	host, err := os.Hostname()
	if err != nil {
		t.Skip("no hostname on this box")
	}
	got, err = nodeID("")
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.ToLower(host) {
		t.Errorf("nodeID(\"\") = %q, want the folded hostname %q", got, strings.ToLower(host))
	}
}

func TestNodeIDTrimsAndFoldsTheExplicitValue(t *testing.T) {
	got, err := nodeID("  Sky142  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sky142" {
		t.Errorf("nodeID = %q, want it trimmed and folded", got)
	}
}
