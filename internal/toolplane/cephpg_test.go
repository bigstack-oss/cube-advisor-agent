package toolplane

import (
	"strings"
	"testing"
)

func TestCephPGIDShape(t *testing.T) {
	for _, ok := range []string{"25.d7", "1.0", "22.d5", "12345.abcdef01"} {
		if !ShapeCephPGID.admits(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "25", ".d7", "25.", "25.D7", "-1.a", "25.d7;rm", "../x", "25.d7.1", "25.g", "123456.a"} {
		if ShapeCephPGID.admits(bad) {
			t.Errorf("%q admitted", bad)
		}
	}
}

func TestPGQueryFillsOnlyAShapedPGID(t *testing.T) {
	var q Tool
	for _, tl := range Allowlist {
		if tl.Name == "ceph_pg_query" {
			q = tl
		}
	}
	argv, err := q.resolve(map[string]string{"{pgid}": "25.d7"})
	if err != nil || strings.Join(argv, " ") != "ceph pg 25.d7 query -f json" {
		t.Fatalf("resolve = %v, %v", argv, err)
	}
	if _, err := q.resolve(map[string]string{"{pgid}": "25.d7 --help"}); err == nil {
		t.Error("a value outside the shape was accepted")
	}
	if _, err := q.resolve(map[string]string{"{other}": "1"}); err == nil {
		t.Error("an undeclared argument was accepted")
	}
}
