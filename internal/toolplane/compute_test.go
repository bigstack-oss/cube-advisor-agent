package toolplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A create on an agent whose operator has enabled writes but has not supplied
// an OpenStack credential must refuse, and must not look like the action level
// refusing.
//
// They are different problems with different owners: one is policy the
// operator chose, the other is configuration they have not finished. An
// operator reading a log needs to know which they are looking at, and a model
// relaying the refusal to a person needs to say the right thing.
func TestACreateWithoutACredentialIsRefusedAndSaysSoDistinctly(t *testing.T) {
	rec := &recorder{}
	r, err := New(Allowlist, rec, WithLevel(LevelOperate))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.ConfigureCubeCOS("dc1", nil)
	r.ConfigureInstanceProfile(InstanceProfile{
		Flavor: "m1.large", Image: "ubuntu-24.04", Network: "tenant-net", Project: "acme-prod",
	})
	// Deliberately no ConfigureWriter.

	_, err = r.Call(context.Background(), "create_instance", map[string]string{"{name}": "web-03"})
	if err == nil {
		t.Fatal("a create with no credential succeeded")
	}
	if errors.Is(err, ErrRefusedAtLevel) {
		t.Error("a missing credential was reported as the action level refusing")
	}
	msg := err.Error()
	if !strings.Contains(msg, "OpenStack credential") {
		t.Errorf("the refusal does not name the missing configuration: %v", err)
	}
	if !strings.Contains(msg, "not the cluster's action level") {
		t.Errorf("the refusal does not distinguish itself from a level refusal: %v", err)
	}
}

// The level still refuses first. A cluster at observe must not reach the
// credential check at all — otherwise an operator at observe would be told to
// go and configure a credential for a tool their level does not serve.
func TestTheLevelRefusesBeforeTheCredentialDoes(t *testing.T) {
	rec := &recorder{}
	r, err := New(Allowlist, rec) // no WithLevel: observe
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.ConfigureCubeCOS("dc1", nil)

	_, err = r.Call(context.Background(), "create_instance", map[string]string{"{name}": "web-03"})
	if err == nil {
		t.Fatal("a create at observe succeeded")
	}
	if strings.Contains(err.Error(), "OpenStack credential") {
		t.Errorf("observe reported a credential problem rather than the level: %v", err)
	}
}

// nova's shape, asserted directly. The allowlist is flat and canonical; this
// is the translation, and it is the part a nova would actually reject if it
// were wrong.
func TestTheNovaBodyIsNovasShapeAndNotTheAllowlists(t *testing.T) {
	raw, err := novaServerBody(map[string]string{
		"name": "web-03", "flavor": "f-1", "image": "i-1", "network": "n-1",
	})
	if err != nil {
		t.Fatalf("novaServerBody: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	server, nested := got["server"].(map[string]any)
	if !nested {
		t.Fatalf("body is not nested under \"server\": %s", raw)
	}
	if server["flavorRef"] != "f-1" {
		t.Errorf("flavorRef = %v; nova does not read \"flavor\"", server["flavorRef"])
	}
	if server["imageRef"] != "i-1" {
		t.Errorf("imageRef = %v; nova does not read \"image\"", server["imageRef"])
	}
	nets, isList := server["networks"].([]any)
	if !isList || len(nets) != 1 {
		t.Fatalf("networks = %v; nova wants a list", server["networks"])
	}
	if n, _ := nets[0].(map[string]any); n["uuid"] != "n-1" {
		t.Errorf("networks[0] = %v, want a uuid object", nets[0])
	}
	if _, named := server["project"]; named {
		t.Error("the body names a project; in nova it is the credential's scope")
	}
}

// A field the profile did not fill must stop the request rather than send a
// server with an empty flavour, which nova would reject with a message about
// the wrong thing.
func TestAnIncompleteProfileStopsTheBodyBeingBuilt(t *testing.T) {
	for _, missing := range []string{"name", "flavor", "image", "network"} {
		fields := map[string]string{
			"name": "web-03", "flavor": "f-1", "image": "i-1", "network": "n-1",
		}
		fields[missing] = ""
		if _, err := novaServerBody(fields); err == nil {
			t.Errorf("a body with no %s was built", missing)
		} else if !strings.Contains(err.Error(), missing) {
			t.Errorf("the error for a missing %s does not name it: %v", missing, err)
		}
	}
}

// cube-cos-api keeps receiving what it always received. The translation is
// nova's, not something imposed on every backend.
func TestTheManagementAPIStillGetsAFlatBody(t *testing.T) {
	raw, err := encodeBody(BackendCubeCOS, map[string]string{"a": "1", "b": "2"})
	if err != nil {
		t.Fatalf("encodeBody: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("not a flat object: %v (%s)", err, raw)
	}
	if got["a"] != "1" || got["b"] != "2" || len(got) != 2 {
		t.Errorf("body = %v", got)
	}
}

// An unrecognised backend has no client, and absence of a client is not
// permission — the same rule an unrecognised impact follows.
func TestAnUnknownBackendHasNoWriter(t *testing.T) {
	rec := &recorder{}
	r, err := New(Allowlist, rec, WithLevel(LevelOperate))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.writerFor(Backend(99)).Post(context.Background(), "/x", nil, "", 1); err == nil {
		t.Error("an unknown backend produced a writer that accepted a post")
	}
}
