package vpn

import (
	"context"
	"strings"
	"testing"
)

// A realistic provider export: comments, IPv6, preshared key, keepalive.
const sampleConf = `
# Exported by ExampleVPN
[Interface]
PrivateKey = VGhpcyBwcml2YXRlIGtleSBpcyAzMiBieXRlcyEhISE=
Address = 10.64.0.2/32, fc00:bbbb::2/128
DNS = 10.64.0.1
MTU = 1380

[Peer]
PublicKey = VGhpcyBwdWJsaWMga2V5IGlzIDMyIGJ5dGVzISEhISE=
PresharedKey = VGhpcyBwcmVzaGFyZWQga2V5IGlzIDMyIGJ5dGVzISE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.net:51820
PersistentKeepalive = 25
`

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig(sampleConf)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Addresses) != 2 || cfg.Addresses[1] != "fc00:bbbb::2/128" {
		t.Fatalf("addresses = %v", cfg.Addresses)
	}
	if cfg.MTU != "1380" || len(cfg.DNS) != 1 {
		t.Fatalf("mtu/dns = %q %v", cfg.MTU, cfg.DNS)
	}
	p := cfg.Peers[0]
	if p.EndpointHost != "vpn.example.net" || p.EndpointPort != "51820" {
		t.Fatalf("endpoint = %q:%q", p.EndpointHost, p.EndpointPort)
	}
	if len(p.AllowedIPs) != 2 || p.PersistentKeepalive != "25" {
		t.Fatalf("peer = %+v", p)
	}

	// The summary must never contain key material.
	sum := cfg.Summary()
	for _, v := range append(append([]string{}, sum.Endpoints...), sum.AllowedIPs...) {
		if strings.Contains(sampleConf, "PrivateKey = "+v) {
			t.Fatalf("summary leaked a key: %q", v)
		}
	}
	if sum.Endpoints[0] != "vpn.example.net:51820" {
		t.Fatalf("summary endpoints = %v", sum.Endpoints)
	}
}

func TestParseConfigRejects(t *testing.T) {
	cases := map[string]string{
		"no peer":       "[Interface]\nPrivateKey = VGhpcyBwcml2YXRlIGtleSBpcyAzMiBieXRlcyEhISE=\nAddress = 10.0.0.2/32",
		"bad key":       strings.Replace(sampleConf, "VGhpcyBwcml2YXRlIGtleSBpcyAzMiBieXRlcyEhISE=", "not-a-key", 1),
		"no address":    strings.Replace(sampleConf, "Address = 10.64.0.2/32, fc00:bbbb::2/128", "", 1),
		"script hook":   sampleConf + "\n[Interface]\nPostUp = rm -rf /",
		"bad endpoint":  strings.Replace(sampleConf, "vpn.example.net:51820", "no-port-here", 1),
		"bad allowedip": strings.Replace(sampleConf, "0.0.0.0/0, ::/0", "not-cidr", 1),
		"unknown key":   sampleConf + "\nBogusOption = 1",
	}
	for name, conf := range cases {
		if _, err := ParseConfig(conf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type recordingRunner struct{ cmds []string }

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	return "", nil
}

func TestImportGeneratesUCI(t *testing.T) {
	cfg, err := ParseConfig(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingRunner{}
	if err := NewUCIConnectorWithRunner(rec).Import(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rec.cmds, "\n")

	for _, want := range []string{
		"network.wg0=interface",
		"network.wg0.proto=wireguard",
		"network.wg0.auto=0",
		"network.wg0.private_key=VGhpcyBwcml2YXRlIGtleSBpcyAzMiBieXRlcyEhISE=",
		"add_list network.wg0.addresses=10.64.0.2/32",
		"add_list network.wg0.addresses=fc00:bbbb::2/128",
		"add_list network.wg0.dns=10.64.0.1",
		"network.wg0.mtu=1380",
		"uci add network wireguard_wg0",
		"network.@wireguard_wg0[-1].public_key=",
		"network.@wireguard_wg0[-1].preshared_key=",
		"add_list network.@wireguard_wg0[-1].allowed_ips=0.0.0.0/0",
		"network.@wireguard_wg0[-1].route_allowed_ips=1",
		"network.@wireguard_wg0[-1].endpoint_host=vpn.example.net",
		"network.@wireguard_wg0[-1].endpoint_port=51820",
		"network.@wireguard_wg0[-1].persistent_keepalive=25",
		"uci commit network",
		"uci commit firewall",
		"/etc/init.d/network reload",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing command containing %q", want)
		}
	}

	// Old state must be cleared before the new one is written.
	if !strings.Contains(rec.cmds[0], "while uci -q delete network.@wireguard_wg0[0]") {
		t.Errorf("import does not clear previous peers first: %q", rec.cmds[0])
	}

	// Up/Down drive netifd.
	c := NewUCIConnectorWithRunner(rec)
	_ = c.Up(context.Background(), Iface)
	_ = c.Down(context.Background(), Iface)
	if rec.cmds[len(rec.cmds)-2] != "ifup wg0" || rec.cmds[len(rec.cmds)-1] != "ifdown wg0" {
		t.Errorf("up/down commands: %v", rec.cmds[len(rec.cmds)-2:])
	}
}
