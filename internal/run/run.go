// Package run is the tiny exec seam shared by packages that shell out to
// OpenWRT tools (uci, ifup, wg, iwinfo, ubus): production code uses Exec,
// tests inject a recorder.
package run

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes an external command and returns its trimmed output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Exec is the production Runner.
type Exec struct{}

func (Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
