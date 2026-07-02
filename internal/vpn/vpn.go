// Package vpn controls a WireGuard tunnel. On the router the default
// connector shells out to wg-quick; tests and dev inject a fake.
package vpn

import (
	"context"
	"os/exec"
	"strings"
)

// Connector brings a WireGuard interface up or down and reports status.
type Connector interface {
	Up(ctx context.Context, iface string) error
	Down(ctx context.Context, iface string) error
	Status(ctx context.Context) (string, error)
}

// ExecConnector is the router implementation: it calls wg-quick / wg.
type ExecConnector struct{}

// Up runs `wg-quick up <iface>`.
func (ExecConnector) Up(ctx context.Context, iface string) error {
	return exec.CommandContext(ctx, "wg-quick", "up", iface).Run()
}

// Down runs `wg-quick down <iface>`.
func (ExecConnector) Down(ctx context.Context, iface string) error {
	return exec.CommandContext(ctx, "wg-quick", "down", iface).Run()
}

// Status returns the trimmed output of `wg show`.
func (ExecConnector) Status(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "wg", "show").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
