package tunnelproto

import (
	"strings"
	"testing"
)

func TestParseDeliverRequest(t *testing.T) {
	ok := map[string]string{"kind": "fixpack", "name": "v3.2.0-001.fixpack", "size": "42", "sha256": strings.Repeat("a", 64)}
	r, err := ParseDeliverRequest(ok)
	if err != nil || r.Size != 42 || r.Kind != PackageFixpack {
		t.Fatalf("parse = %+v, %v", r, err)
	}
	if got := r.Args(); got["size"] != "42" || got["name"] != ok["name"] {
		t.Errorf("args = %v", got)
	}
	for name, mod := range map[string]func(m map[string]string){
		"unknown kind": func(m map[string]string) { m["kind"] = "agent" },
		"path":         func(m map[string]string) { m["name"] = "a/b.pkg" },
		"dot dot":      func(m map[string]string) { m["name"] = "a..pkg" },
		"hidden":       func(m map[string]string) { m["name"] = ".x.pkg" },
		"zero size":    func(m map[string]string) { m["size"] = "0" },
		"huge":         func(m map[string]string) { m["size"] = "999999999999999" },
		"short sha":    func(m map[string]string) { m["sha256"] = "abc" },
		"upper sha":    func(m map[string]string) { m["sha256"] = strings.Repeat("A", 64) },
		"extra arg":    func(m map[string]string) { m["dest"] = "/etc" },
	} {
		m := map[string]string{}
		for k, v := range ok {
			m[k] = v
		}
		mod(m)
		if _, err := ParseDeliverRequest(m); err == nil {
			t.Errorf("%s: accepted %v", name, m)
		}
	}
}
