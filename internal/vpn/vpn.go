// Package vpn controls a WireGuard tunnel the OpenWRT way: the parsed
// config is written as UCI (proto wireguard, netifd-managed) and the
// tunnel is driven with ifup/ifdown. wg-quick is only the *import format*
// (config.go) — the tool itself needs bash and doesn't exist on OpenWRT.
package vpn

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Iface is the managed UCI interface (and kernel device) name. The peer
// section type wireguard_<iface> is derived from it, per netifd convention.
const Iface = "wg0"

// Connector imports a WireGuard config and brings the tunnel up or down.
type Connector interface {
	Import(ctx context.Context, cfg *Config) error
	Up(ctx context.Context, iface string) error
	Down(ctx context.Context, iface string) error
	Status(ctx context.Context) (string, error)
}

// Runner executes an external command — injectable so tests can record
// the exact UCI writes instead of mutating a router.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// UCIConnector is the router implementation.
type UCIConnector struct{ run Runner }

// NewUCIConnector returns the production connector.
func NewUCIConnector() UCIConnector { return UCIConnector{run: execRunner{}} }

// NewUCIConnectorWithRunner is the test seam.
func NewUCIConnectorWithRunner(r Runner) UCIConnector { return UCIConnector{run: r} }

// Import replaces the wg0 UCI config with cfg and registers the interface
// with netifd (auto=0: the tunnel comes up only when the user connects).
// The private key lands in /etc/config/network — root-only UCI state, the
// same place OpenWRT keeps Wi-Fi credentials — and nowhere else.
func (c UCIConnector) Import(ctx context.Context, cfg *Config) error {
	peerType := "wireguard_" + Iface

	cmds := [][]string{
		// Clear any previous import (idempotent re-import).
		{"sh", "-c", fmt.Sprintf("while uci -q delete network.@%s[0]; do :; done", peerType)},
		{"sh", "-c", fmt.Sprintf("uci -q delete network.%s || true", Iface)},
		{"uci", "set", fmt.Sprintf("network.%s=interface", Iface)},
		{"uci", "set", fmt.Sprintf("network.%s.proto=wireguard", Iface)},
		{"uci", "set", fmt.Sprintf("network.%s.auto=0", Iface)},
		{"uci", "set", fmt.Sprintf("network.%s.private_key=%s", Iface, cfg.PrivateKey)},
	}
	for _, a := range cfg.Addresses {
		cmds = append(cmds, []string{"uci", "add_list", fmt.Sprintf("network.%s.addresses=%s", Iface, a)})
	}
	for _, d := range cfg.DNS {
		cmds = append(cmds, []string{"uci", "add_list", fmt.Sprintf("network.%s.dns=%s", Iface, d)})
	}
	if cfg.MTU != "" {
		cmds = append(cmds, []string{"uci", "set", fmt.Sprintf("network.%s.mtu=%s", Iface, cfg.MTU)})
	}

	for _, p := range cfg.Peers {
		cmds = append(cmds, []string{"uci", "add", "network", peerType})
		set := func(k, v string) {
			cmds = append(cmds, []string{"uci", "set", fmt.Sprintf("network.@%s[-1].%s=%s", peerType, k, v)})
		}
		set("public_key", p.PublicKey)
		if p.PresharedKey != "" {
			set("preshared_key", p.PresharedKey)
		}
		for _, a := range p.AllowedIPs {
			cmds = append(cmds, []string{"uci", "add_list", fmt.Sprintf("network.@%s[-1].allowed_ips=%s", peerType, a)})
		}
		// Route what the peer carries; with 0.0.0.0/0 that is the kill-
		// switch-less "route everything through the tunnel" default.
		set("route_allowed_ips", "1")
		if p.EndpointHost != "" {
			set("endpoint_host", p.EndpointHost)
			set("endpoint_port", p.EndpointPort)
		}
		if p.PersistentKeepalive != "" {
			set("persistent_keepalive", p.PersistentKeepalive)
		}
	}

	cmds = append(cmds,
		[]string{"uci", "commit", "network"},
		// Attach wg0 to the wan firewall zone (found by name, not index)
		// so LAN→tunnel forwarding + masquerade apply.
		[]string{"sh", "-c", fmt.Sprintf(
			`zone=$(uci show firewall | sed -n "s/^firewall\.\(@zone\[[0-9]*\]\)\.name='wan'$/\1/p" | head -1); `+
				`[ -n "$zone" ] || exit 1; `+
				`uci -q get firewall.$zone.network | grep -qw %s || uci add_list firewall.$zone.network=%s; `+
				`uci commit firewall`, Iface, Iface)},
		// Let netifd learn the interface; auto=0 keeps it down until Up().
		[]string{"/etc/init.d/network", "reload"},
	)

	for _, argv := range cmds {
		if _, err := c.run.Run(ctx, argv[0], argv[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// Up starts the tunnel via netifd.
func (c UCIConnector) Up(ctx context.Context, iface string) error {
	_, err := c.run.Run(ctx, "ifup", iface)
	return err
}

// Down stops the tunnel via netifd.
func (c UCIConnector) Down(ctx context.Context, iface string) error {
	_, err := c.run.Run(ctx, "ifdown", iface)
	return err
}

// Status returns `wg show <iface>` output; an error (interface absent)
// simply means the tunnel is down.
func (c UCIConnector) Status(ctx context.Context) (string, error) {
	return c.run.Run(ctx, "wg", "show", Iface)
}
