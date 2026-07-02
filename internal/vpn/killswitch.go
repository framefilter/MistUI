// The kill switch. Import() gives wg0 its own 'vpn' firewall zone with a
// standing lan→vpn forwarding, so client traffic may always use the tunnel.
// The switch itself is the presence of the lan→wan forwarding: ON deletes
// it (clients cannot reach the uplink directly, tunnel or nothing), OFF
// restores it. State therefore lives in the firewall config itself —
// nothing extra to persist, and it survives reboots by construction.
//
// Scope: this governs *forwarded* client traffic. Router-originated
// traffic (e.g. dnsmasq's upstream queries while the tunnel is down) is
// OUTPUT, not FORWARD — that leak is closed by encrypted DNS
// (internal/dns): plaintext port 53 is rejected on the wan zone outright,
// and while this switch is on a companion rule (mistui_dns_ks, installed
// by the killswitch handler) rejects DoH on the raw wan too. If the user
// turns encrypted DNS off, the OUTPUT leak returns and the UI says so.
package vpn

import (
	"context"
	"fmt"
)

const findLanWanForwarding = `uci show firewall | sed -n "s/^firewall\.\(@forwarding\[[0-9]*\]\)\.src='lan'$/\1/p"`

// SetKillSwitch enables or disables the kill switch.
func (c UCIConnector) SetKillSwitch(ctx context.Context, enabled bool) error {
	var script string
	if enabled {
		// Delete every lan→wan forwarding, one at a time (indices shift).
		script = `changed=0; while :; do found=""; ` +
			`for s in $(` + findLanWanForwarding + `); do ` +
			`[ "$(uci -q get firewall.$s.dest)" = "wan" ] && { found=$s; break; }; done; ` +
			`[ -n "$found" ] || break; uci delete firewall.$found; changed=1; done; ` +
			`[ "$changed" = 1 ] && { uci commit firewall; /etc/init.d/firewall reload; } || true`
	} else {
		script = `have=""; for s in $(` + findLanWanForwarding + `); do ` +
			`[ "$(uci -q get firewall.$s.dest)" = "wan" ] && have=1; done; ` +
			`[ -n "$have" ] || { uci add firewall forwarding >/dev/null; ` +
			`uci set firewall.@forwarding[-1].src=lan; uci set firewall.@forwarding[-1].dest=wan; ` +
			`uci commit firewall; /etc/init.d/firewall reload; }`
	}
	if _, err := c.run.Run(ctx, "sh", "-c", script); err != nil {
		return err
	}
	// Removing the forwarding only stops NEW connections — fw4 accepts
	// established flows before zone rules run, so anything already open
	// would keep leaking. Flush conntrack so every flow re-classifies
	// against the rules that now exist.
	if enabled && c.flushCT != nil {
		if err := c.flushCT(); err != nil {
			return fmt.Errorf("kill switch set, but conntrack flush failed: %w", err)
		}
	}
	return nil
}

// KillSwitch reports whether the switch is on (no lan→wan forwarding).
func (c UCIConnector) KillSwitch(ctx context.Context) (bool, error) {
	script := `for s in $(` + findLanWanForwarding + `); do ` +
		`[ "$(uci -q get firewall.$s.dest)" = "wan" ] && { echo off; exit 0; }; done; echo on`
	out, err := c.run.Run(ctx, "sh", "-c", script)
	if err != nil {
		return false, err
	}
	return out == "on", nil
}
