package toolplane

import (
	"context"
	"encoding/json"
	"fmt"
)

// novaServerBody renders the allowlist's canonical fields as nova's create
// request.
//
// The translation lives here rather than in the transport so that the
// transport stays a pipe: something that holds a base URL, a token and a TLS
// config and posts bytes. That split is what makes the wire shape testable
// without a nova to talk to, and it is why this function takes a map and
// returns bytes rather than reaching for a client.
//
// nova's shape is not the allowlist's, and the differences are the reason this
// exists rather than a marshal of the flat map:
//
//   - the object is nested under "server";
//   - the flavour and image are flavorRef and imageRef, and are ids, not names;
//   - networks is a list of objects, because a server may have several — the
//     allowlist offers one because an operator's profile names one, and a list
//     of one is how nova is told that.
//
// There is no project field. A server is created in the project the
// credential is scoped to, which is the control described on the tool: a
// project that cannot be named cannot be named wrongly.
func novaServerBody(fields map[string]string) ([]byte, error) {
	for _, f := range []string{"name", "flavor", "image", "network"} {
		if fields[f] == "" {
			return nil, fmt.Errorf("no %s resolved for the create request", f)
		}
	}
	type novaNetwork struct {
		UUID string `json:"uuid"`
	}
	type novaServer struct {
		Name      string        `json:"name"`
		FlavorRef string        `json:"flavorRef"`
		ImageRef  string        `json:"imageRef"`
		Networks  []novaNetwork `json:"networks"`
	}
	return json.Marshal(struct {
		Server novaServer `json:"server"`
	}{novaServer{
		Name:      fields["name"],
		FlavorRef: fields["flavor"],
		ImageRef:  fields["image"],
		Networks:  []novaNetwork{{UUID: fields["network"]}},
	}})
}

// encodeBody renders a resolved body for the backend it is going to.
//
// A backend that has no translation sends the canonical fields as they stand,
// which is what cube-cos-api has always received.
func encodeBody(b Backend, fields map[string]string) ([]byte, error) {
	if b == BackendOpenStackCompute {
		return novaServerBody(fields)
	}
	return json.Marshal(fields)
}

// notConfiguredCompute is the default compute writer: an agent whose operator
// has not given it OpenStack credentials refuses a create cleanly.
//
// The wording matters and is not interchangeable with a level refusal. "The
// level forbids it" and "nobody gave me a credential" are different problems
// with different owners — one is policy the operator chose, the other is
// configuration they have not finished — and an operator reading a log needs
// to know which they are looking at. A level refusal travels as
// tunnelproto.RefusedAtLevelReason; this is an ordinary configuration error and
// deliberately carries no such marker.
type notConfiguredCompute struct{}

func (notConfiguredCompute) Post(context.Context, string, []byte, string, int) ([]byte, error) {
	return nil, fmt.Errorf("this agent has no OpenStack credential configured; " +
		"an operator must add one before it can create anything. " +
		"This is not the cluster's action level refusing: it is missing configuration")
}
