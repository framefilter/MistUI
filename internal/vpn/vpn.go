// Package vpn controls a WireGuard tunnel the OpenWRT way: the parsed
// config is written as UCI (proto wireguard, netifd-managed) and the
// tunnel is driven with ifup/ifdown. wg-quick is only the *import format*
// (config.go) — the tool itself needs bash and doesn't exist on OpenWRT.
package vpn

import (
	"context"
	"fmt"

	"github.com/framefilter/mistui/internal/run"
)

// Iface is the managed UCI interface (and kernel device) name. The peer
// section type wireguard_<iface> is derived from it, per netifd convention.
const Iface = "wg0"

// Connector imports a WireGuard config, brings the tunnel up or down, and
// controls the kill switch.
type Connector interface {
	Import(ctx context.Context, cfg *Config) error
	Up(ctx context.Context, iface string) error
	Down(ctx context.Context, iface string) error
	Status(ctx context.Context) (string, error)
	SetKillSwitch(ctx context.Context, enabled bool) error
	KillSwitch(ctx context.Context) (bool, error)
}

// UCIConnector is the router implementation.
type UCIConnector struct{ run run.Runner }

// NewUCIConnector returns the production connector.
func NewUCIConnector() UCIConnector { return UCIConnector{run: run.Exec{}} }

// NewUCIConnectorWithRunner is the test seam.
func NewUCIConnectorWithRunner(r run.Runner) UCIConnector { return UCIConnector{run: r} }

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
		// wg0 lives in its own 'vpn' zone (masq + mtu_fix) with a standing
		// lan→vpn forwarding. The kill switch then has exactly one lever:
		// the lan→wan forwarding (see SetKillSwitch) — tunnel traffic is
		// always allowed, direct WAN is what gets revoked.
		[]string{"sh", "-c", fmt.Sprintf(
			`uci show firewall | grep -q "\.name='vpn'" || { `+
				`uci add firewall zone >/dev/null; `+
				`uci set firewall.@zone[-1].name=vpn; `+
				`uci add_list firewall.@zone[-1].network=%s; `+
				`uci set firewall.@zone[-1].input=REJECT; `+
				`uci set firewall.@zone[-1].output=ACCEPT; `+
				`uci set firewall.@zone[-1].forward=REJECT; `+
				`uci set firewall.@zone[-1].masq=1; `+
				`uci set firewall.@zone[-1].mtu_fix=1; `+
				`uci add firewall forwarding >/dev/null; `+
				`uci set firewall.@forwarding[-1].src=lan; `+
				`uci set firewall.@forwarding[-1].dest=vpn; `+
				`uci commit firewall; }`, Iface)},
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
