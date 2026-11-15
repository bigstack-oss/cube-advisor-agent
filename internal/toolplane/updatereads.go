package toolplane

import (
	"context"
	"fmt"
	"time"

	"github.com/bigstack-oss/cube-advisor-agent/pkg/tunnelproto"
)

// UpdateReadTools are the install flow's fixed reads: the roll's dry run
// and the fixpack status and history. Each runs one documented hex_cli
// command, read-only in CubeCOS, with no caller text. run nil uses exec.
func UpdateReadTools(run func(ctx context.Context, argv []string, maxBytes int) ([]byte, error)) []Tool {
	if run == nil {
		run = runCommand
	}
	var out []Tool
	for _, name := range []string{tunnelproto.RollDryrunTool, tunnelproto.FixpackStatusTool, tunnelproto.FixpackHistoryTool} {
		argv := tunnelproto.UpdateReadArgv[name]
		out = append(out, Tool{
			Name:        name,
			Description: fmt.Sprintf("Run `%s` (read-only).", joinArgv(argv)),
			Timeout:     90 * time.Second,
			Local: func(ctx context.Context, args map[string]string) ([]byte, error) {
				if len(args) > 0 {
					return nil, fmt.Errorf("%s takes no arguments", name)
				}
				b, err := run(ctx, argv, 256<<10)
				if err != nil {
					return nil, fmt.Errorf("%s: %v: %s", name, err, b)
				}
				return b, nil
			},
		})
	}
	return out
}

func joinArgv(argv []string) string {
	s := ""
	for i, a := range argv {
		if i > 0 {
			s += " "
		}
		s += a
	}
	return s
}
