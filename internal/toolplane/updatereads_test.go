package toolplane

import (
	"context"
	"strings"
	"testing"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

type nopAudit struct{ calls []ToolCall }

func (a *nopAudit) RecordToolCall(c ToolCall) { a.calls = append(a.calls, c) }

func TestUpdateReadsRunTheirFixedCommandOnly(t *testing.T) {
	var ran [][]string
	run := func(_ context.Context, argv []string, _ int) ([]byte, error) {
		ran = append(ran, argv)
		return []byte("plan"), nil
	}
	a := &nopAudit{}
	reg, err := New(UpdateReadTools(run), a)
	if err != nil {
		t.Fatal(err)
	}
	out, err := reg.Call(context.Background(), tunnelproto.RollDryrunTool, nil)
	if err != nil || string(out) != "plan" {
		t.Fatalf("dryrun = %q, %v", out, err)
	}
	if got := strings.Join(ran[0], " "); got != "/usr/sbin/hex_cli -c cluster -c rolling_update dryrun" {
		t.Errorf("ran %q", got)
	}
	if _, err := reg.Call(context.Background(), tunnelproto.FixpackStatusTool, map[string]string{"id": "x; rm -rf /"}); err == nil {
		t.Error("an argument was accepted")
	}
	if len(ran) != 1 || len(a.calls) != 2 || a.calls[1].Allowed {
		t.Errorf("ran %v, audit %+v", ran, a.calls)
	}
}
