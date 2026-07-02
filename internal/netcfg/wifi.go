// Wi-Fi configuration: the travel AP and the hotel-uplink STA, both as UCI
// on the single radio (§2: AP+STA share the 2.4 GHz band on the Mango).
// MistUI owns two named wifi-iface sections — mistui_ap and mistui_sta —
// and never touches radio/board config beyond enabling the radio.
package netcfg

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/framefilter/mistui/internal/run"
)

const (
	apSection  = "mistui_ap"
	staSection = "mistui_sta"
	// wwan is the conventional OpenWRT name for a wireless uplink.
	uplinkNet = "wwan"
)

// WiFi performs wireless configuration through UCI/ubus.
type WiFi struct{ run run.Runner }

// NewWiFi returns the production implementation.
func NewWiFi() WiFi { return WiFi{run: run.Exec{}} }

// NewWiFiWithRunner is the test seam.
func NewWiFiWithRunner(r run.Runner) WiFi { return WiFi{run: r} }

// Network is one scan result.
type Network struct {
	SSID       string `json:"ssid"`
	Signal     int    `json:"signal"`
	Encryption string `json:"encryption"` // "none" or "psk"
}

// Status reports both sides of the radio.
type Status struct {
	APSSID     string `json:"apSsid,omitempty"`
	APEnabled  bool   `json:"apEnabled"`
	UplinkSSID string `json:"uplinkSsid,omitempty"`
	UplinkUp   bool   `json:"uplinkUp"`
	UplinkIP   string `json:"uplinkIp,omitempty"`
}

func validSSID(s string) error {
	if n := len(s); n < 1 || n > 32 {
		return fmt.Errorf("SSID must be 1–32 bytes, got %d", n)
	}
	return nil
}

func validPSK(k string) error {
	if n := len(k); n < 8 || n > 63 {
		return fmt.Errorf("Wi-Fi password must be 8–63 characters, got %d", n)
	}
	return nil
}

// SetAP configures the travel network (WPA2-PSK on the LAN bridge) and
// enables the radio. This is the wizard's first network step — the radio
// must be up before Scan can see anything.
func (w WiFi) SetAP(ctx context.Context, ssid, key string) error {
	if err := validSSID(ssid); err != nil {
		return err
	}
	if err := validPSK(key); err != nil {
		return err
	}
	cmds := [][]string{
		// The stock placeholder AP (disabled, open) has no place here.
		{"sh", "-c", "uci -q delete wireless.default_radio0 || true"},
		{"uci", "set", "wireless.radio0.disabled=0"},
		{"uci", "set", "wireless." + apSection + "=wifi-iface"},
		{"uci", "set", "wireless." + apSection + ".device=radio0"},
		{"uci", "set", "wireless." + apSection + ".network=lan"},
		{"uci", "set", "wireless." + apSection + ".mode=ap"},
		{"uci", "set", "wireless." + apSection + ".ssid=" + ssid},
		{"uci", "set", "wireless." + apSection + ".encryption=psk2"},
		{"uci", "set", "wireless." + apSection + ".key=" + key},
		{"uci", "commit", "wireless"},
		{"wifi", "reload"},
	}
	return w.runAll(ctx, cmds)
}

// JoinUplink points the STA at an upstream network (empty key = open, the
// typical captive-portal hotel case). A non-nil ident applies its spoofed
// MAC + DHCP hostname *before* association — §5.1: the identity the hotel
// sees is set once, up front, never rolled while a portal grant is live.
func (w WiFi) JoinUplink(ctx context.Context, ssid, key string, ident *Identity) error {
	if err := validSSID(ssid); err != nil {
		return err
	}
	enc := "none"
	if key != "" {
		if err := validPSK(key); err != nil {
			return err
		}
		enc = "psk2"
	}
	cmds := [][]string{
		{"uci", "set", "wireless." + staSection + "=wifi-iface"},
		{"uci", "set", "wireless." + staSection + ".device=radio0"},
		{"uci", "set", "wireless." + staSection + ".network=" + uplinkNet},
		{"uci", "set", "wireless." + staSection + ".mode=sta"},
		{"uci", "set", "wireless." + staSection + ".ssid=" + ssid},
		{"uci", "set", "wireless." + staSection + ".encryption=" + enc},
	}
	if key != "" {
		cmds = append(cmds, []string{"uci", "set", "wireless." + staSection + ".key=" + key})
	} else {
		cmds = append(cmds, []string{"sh", "-c", "uci -q delete wireless." + staSection + ".key || true"})
	}
	cmds = append(cmds, macCmds(ident)...)
	cmds = append(cmds,
		[]string{"uci", "set", "network." + uplinkNet + "=interface"},
		[]string{"uci", "set", "network." + uplinkNet + ".proto=dhcp"},
	)
	cmds = append(cmds, hostnameCmds(ident)...)
	cmds = append(cmds,
		[]string{"uci", "commit", "wireless"},
		[]string{"uci", "commit", "network"},
		// The uplink lives in the wan zone (masquerade, input reject).
		[]string{"sh", "-c", fmt.Sprintf(
			`zone=$(uci show firewall | sed -n "s/^firewall\.\(@zone\[[0-9]*\]\)\.name='wan'$/\1/p" | head -1); `+
				`[ -n "$zone" ] || exit 1; `+
				`uci -q get firewall.$zone.network | grep -qw %s || uci add_list firewall.$zone.network=%s; `+
				`uci commit firewall`, uplinkNet, uplinkNet)},
		[]string{"/etc/init.d/network", "reload"},
		[]string{"wifi", "reload"},
	)
	return w.runAll(ctx, cmds)
}

// Scan lists visible networks via the first up wireless device. The radio
// must be enabled (SetAP) first; we scan from the AP interface. Radio
// bring-up after `wifi reload` is asynchronous, so wait for it briefly
// instead of failing a scan clicked right after AP creation.
func (w WiFi) Scan(ctx context.Context) ([]Network, error) {
	dev, err := w.upDevice(ctx)
	for i := 0; err != nil && i < 10; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
		dev, err = w.upDevice(ctx)
	}
	if err != nil {
		return nil, err
	}
	out, err := w.run.Run(ctx, "ubus", "call", "iwinfo", "scan", fmt.Sprintf(`{"device":%q}`, dev))
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Results []struct {
			SSID       string `json:"ssid"`
			Signal     int    `json:"signal"`
			Encryption struct {
				Enabled bool `json:"enabled"`
			} `json:"encryption"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, fmt.Errorf("scan parse: %w", err)
	}
	seen := map[string]bool{}
	var nets []Network
	for _, r := range parsed.Results {
		if r.SSID == "" || seen[r.SSID] {
			continue
		}
		seen[r.SSID] = true
		enc := "none"
		if r.Encryption.Enabled {
			enc = "psk"
		}
		nets = append(nets, Network{SSID: r.SSID, Signal: r.Signal, Encryption: enc})
	}
	return nets, nil
}

// Status reports AP config and uplink state.
func (w WiFi) Status(ctx context.Context) (Status, error) {
	var st Status
	if ssid, err := w.run.Run(ctx, "uci", "-q", "get", "wireless."+apSection+".ssid"); err == nil && ssid != "" {
		st.APSSID, st.APEnabled = ssid, true
	}
	if ssid, err := w.run.Run(ctx, "uci", "-q", "get", "wireless."+staSection+".ssid"); err == nil {
		st.UplinkSSID = ssid
	}
	out, err := w.run.Run(ctx, "ubus", "call", "network.interface."+uplinkNet, "status")
	if err != nil {
		return st, nil // uplink never configured; not an error
	}
	var ifc struct {
		Up   bool `json:"up"`
		IPv4 []struct {
			Address string `json:"address"`
		} `json:"ipv4-address"`
	}
	if json.Unmarshal([]byte(out), &ifc) == nil {
		st.UplinkUp = ifc.Up
		if len(ifc.IPv4) > 0 {
			st.UplinkIP = ifc.IPv4[0].Address
		}
	}
	return st, nil
}

// macCmds sets (or clears) the STA MAC for ident. A nil ident or empty MAC
// clears the override, restoring the hardware address.
func macCmds(ident *Identity) [][]string {
	if ident == nil || ident.MAC == "" {
		return [][]string{{"sh", "-c", "uci -q delete wireless." + staSection + ".macaddr || true"}}
	}
	return [][]string{{"uci", "set", "wireless." + staSection + ".macaddr=" + ident.MAC}}
}

// hostnameCmds sets (or clears) the uplink DHCP hostname for ident.
func hostnameCmds(ident *Identity) [][]string {
	if ident == nil || ident.Hostname == "" {
		return [][]string{{"sh", "-c", "uci -q delete network." + uplinkNet + ".hostname || true"}}
	}
	return [][]string{{"uci", "set", "network." + uplinkNet + ".hostname=" + ident.Hostname}}
}

// ApplySTAIdentity rewrites the uplink's spoofed MAC + DHCP hostname on an
// already-configured uplink and reloads wifi. The reload drops any live
// association — callers gate this on schedule/user intent (§5.1: a
// captive-portal grant is bound to the MAC and dies with it).
func (w WiFi) ApplySTAIdentity(ctx context.Context, ident Identity) error {
	if _, err := w.run.Run(ctx, "uci", "-q", "get", "wireless."+staSection); err != nil {
		return fmt.Errorf("no uplink configured yet")
	}
	cmds := append(macCmds(&ident), hostnameCmds(&ident)...)
	cmds = append(cmds,
		[]string{"uci", "commit", "wireless"},
		[]string{"uci", "commit", "network"},
		// Re-DHCP so the new hostname is sent, and re-associate so the new
		// MAC takes effect.
		[]string{"/etc/init.d/network", "reload"},
		[]string{"wifi", "reload"},
	)
	return w.runAll(ctx, cmds)
}

// upDevice returns the OS name of an up wireless interface (per netifd).
func (w WiFi) upDevice(ctx context.Context) (string, error) {
	out, err := w.run.Run(ctx, "ubus", "call", "network.wireless", "status")
	if err != nil {
		return "", err
	}
	var radios map[string]struct {
		Up         bool `json:"up"`
		Interfaces []struct {
			Ifname string `json:"ifname"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal([]byte(out), &radios); err != nil {
		return "", fmt.Errorf("wireless status parse: %w", err)
	}
	for _, r := range radios {
		if !r.Up {
			continue
		}
		for _, i := range r.Interfaces {
			if i.Ifname != "" {
				return i.Ifname, nil
			}
		}
	}
	return "", fmt.Errorf("no wireless interface is up — set the travel Wi-Fi first")
}

func (w WiFi) runAll(ctx context.Context, cmds [][]string) error {
	for _, argv := range cmds {
		if _, err := w.run.Run(ctx, argv[0], argv[1:]...); err != nil {
			return err
		}
	}
	return nil
}
