package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/internal/toolplane"
)

func TestNodeRoleReadsCubesysPolicy(t *testing.T) {
	old := cubesysPolicy
	t.Cleanup(func() { cubesysPolicy = old })

	cubesysPolicy = filepath.Join(t.TempDir(), "missing.yml")
	if got := nodeRole(); got != "" {
		t.Errorf("no policy: role %q, want empty", got)
	}
	cubesysPolicy = filepath.Join(t.TempDir(), "cubesys1_0.yml")
	_ = os.WriteFile(cubesysPolicy, []byte("---\nname: cubesys\n# role: x\nrole: compute\nha: true\n"), 0o644)
	if got := nodeRole(); got != "compute" {
		t.Errorf("role %q, want compute", got)
	}
	reg, err := toolplane.New(nil, nopAuditor{})
	if err != nil {
		t.Fatal(err)
	}
	if got := helloFor("c", "f", reg).NodeRole; got != "compute" {
		t.Errorf("hello carries role %q", got)
	}
}
