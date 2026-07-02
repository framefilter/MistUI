// The router side of encrypted DNS: dnsmasq forwards every lookup — LAN
// clients' and the router's own — to the embedded DoH forwarder, and the
// firewall stops anything that would go around it. Like the kill switch,
// all state lives in UCI itself: nothing extra to persist, reboot-safe by
// construction.
//
// Named firewall sections owned by this package:
//
//	mistui_dns_out    reject router-originated port 53 out the wan zone —
//	                  the OUTPUT leak the kill switch could never close
//	mistui_dns_fwd    reject forwarded lan→wan port 53 (defense in depth;
//	                  the hijack below normally catches these first)
//	mistui_dns_hijack DNAT any LAN port-53 query to the router, so devices
//	                  with hardcoded resolvers stay working — and encrypted
//	mistui_dns_ks     the fail-closed rule: reject router→resolver:443 on
//	                  the raw wan zone. Present only while the kill switch
//	                  is on. With the tunnel up, DoH egresses via wg0 (vpn
//	                  zone) and never matches; tunnel down, DNS fails closed.
package dns

import (
	"context"
	"net"
	"strings"

	"github.com/framefilter/mistui/internal/run"
)

// Service applies the UCI/firewall side of encrypted DNS.
type Service struct {
	run run.Runner
	Fwd *Forwarder
}

// NewService returns the production implementation.
func NewService(f *Forwarder) *Service { return &Service{run: run.Exec{}, Fwd: f} }

// NewServiceWithRunner is the test seam.
func NewServiceWithRunner(f *Forwarder, r run.Runner) *Service {
	return &Service{run: r, Fwd: f}
}

// serverSpec is the dnsmasq upstream syntax for the forwarder (host#port).
func (s *Service) serverSpec() string {
	host, port, err := net.SplitHostPort(s.Fwd.Addr())
	if err != nil {
		host, port = "127.0.0.1", "5335"
	}
	return host + "#" + port
}

// Enable points dnsmasq exclusively at the forwarder and installs the
// port-53 leak rules. Idempotent.
func (s *Service) Enable(ctx context.Context) error {
	spec := s.serverSpec()
	cmds := [][]string{
		// noresolv: never fall back to the DHCP-provided (hotel) resolvers.
		{"uci", "set", "dhcp.@dnsmasq[0].noresolv=1"},
		{"sh", "-c", "uci -q del_list 'dhcp.@dnsmasq[0].server=" + spec + "' || true"},
		{"uci", "add_list", "dhcp.@dnsmasq[0].server=" + spec},
		{"uci", "commit", "dhcp"},

		{"uci", "set", "firewall.mistui_dns_out=rule"},
		{"uci", "set", "firewall.mistui_dns_out.name=mistui-dns53-out"},
		{"uci", "set", "firewall.mistui_dns_out.dest=wan"}, // no src ⇒ OUTPUT
		{"uci", "set", "firewall.mistui_dns_out.proto=tcp udp"},
		{"uci", "set", "firewall.mistui_dns_out.dest_port=53"},
		{"uci", "set", "firewall.mistui_dns_out.target=REJECT"},

		{"uci", "set", "firewall.mistui_dns_fwd=rule"},
		{"uci", "set", "firewall.mistui_dns_fwd.name=mistui-dns53-fwd"},
		{"uci", "set", "firewall.mistui_dns_fwd.src=lan"},
		{"uci", "set", "firewall.mistui_dns_fwd.dest=wan"},
		{"uci", "set", "firewall.mistui_dns_fwd.proto=tcp udp"},
		{"uci", "set", "firewall.mistui_dns_fwd.dest_port=53"},
		{"uci", "set", "firewall.mistui_dns_fwd.target=REJECT"},

		{"uci", "set", "firewall.mistui_dns_hijack=redirect"},
		{"uci", "set", "firewall.mistui_dns_hijack.name=mistui-dns-hijack"},
		{"uci", "set", "firewall.mistui_dns_hijack.src=lan"},
		{"uci", "set", "firewall.mistui_dns_hijack.proto=tcp udp"},
		{"uci", "set", "firewall.mistui_dns_hijack.src_dport=53"},
		{"uci", "set", "firewall.mistui_dns_hijack.target=DNAT"},

		{"uci", "commit", "firewall"},
		{"/etc/init.d/dnsmasq", "restart"},
		{"/etc/init.d/firewall", "reload"},
	}
	return s.runAll(ctx, cmds)
}

// Disable restores plain resolv.conf-driven DNS and removes every rule this
// package owns — including the fail-closed rule: with no DoH there is
// nothing for it to govern (the UI states plainly that the kill switch's
// port-53 OUTPUT leak is back).
func (s *Service) Disable(ctx context.Context) error {
	spec := s.serverSpec()
	cmds := [][]string{
		{"sh", "-c", "uci -q delete dhcp.@dnsmasq[0].noresolv || true"},
		{"sh", "-c", "uci -q del_list 'dhcp.@dnsmasq[0].server=" + spec + "' || true"},
		{"uci", "commit", "dhcp"},
		{"sh", "-c", "uci -q delete firewall.mistui_dns_out || true"},
		{"sh", "-c", "uci -q delete firewall.mistui_dns_fwd || true"},
		{"sh", "-c", "uci -q delete firewall.mistui_dns_hijack || true"},
		{"sh", "-c", "uci -q delete firewall.mistui_dns_ks || true"},
		{"uci", "commit", "firewall"},
		{"/etc/init.d/dnsmasq", "restart"},
		{"/etc/init.d/firewall", "reload"},
	}
	return s.runAll(ctx, cmds)
}

// Enabled reports whether dnsmasq currently forwards to the DoH forwarder.
func (s *Service) Enabled(ctx context.Context) (bool, error) {
	out, err := s.run.Run(ctx, "sh", "-c",
		"uci -q get 'dhcp.@dnsmasq[0].server' | grep -qF '"+s.serverSpec()+"' && echo on || echo off")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "on", nil
}

// SetFailClosed installs or removes the kill-switch companion rule (see the
// package comment's mistui_dns_ks entry). The deny-list is the union of all
// curated resolver addresses, so switching providers never needs a resync.
func (s *Service) SetFailClosed(ctx context.Context, on bool) error {
	var cmds [][]string
	if on {
		cmds = [][]string{
			{"uci", "set", "firewall.mistui_dns_ks=rule"},
			{"uci", "set", "firewall.mistui_dns_ks.name=mistui-doh-failclosed"},
			{"uci", "set", "firewall.mistui_dns_ks.dest=wan"}, // no src ⇒ OUTPUT
			{"uci", "set", "firewall.mistui_dns_ks.proto=tcp"},
			{"uci", "set", "firewall.mistui_dns_ks.dest_port=443"},
			{"sh", "-c", "uci -q delete firewall.mistui_dns_ks.dest_ip || true"},
		}
		for _, ip := range AllResolverIPs() {
			cmds = append(cmds, []string{"uci", "add_list", "firewall.mistui_dns_ks.dest_ip=" + ip})
		}
		cmds = append(cmds,
			[]string{"uci", "set", "firewall.mistui_dns_ks.target=REJECT"},
			[]string{"uci", "commit", "firewall"},
			[]string{"/etc/init.d/firewall", "reload"},
		)
		if err := s.runAll(ctx, cmds); err != nil {
			return err
		}
		// The rule only stops new connections; a warm keep-alive DoH
		// connection would sail through it. Cut the pool so the next
		// lookup has to dial — and be rejected.
		s.Fwd.CloseUpstream()
		return nil
	} else {
		cmds = [][]string{
			{"sh", "-c", "uci -q delete firewall.mistui_dns_ks || true"},
			{"uci", "commit", "firewall"},
			{"/etc/init.d/firewall", "reload"},
		}
	}
	return s.runAll(ctx, cmds)
}

func (s *Service) runAll(ctx context.Context, cmds [][]string) error {
	for _, argv := range cmds {
		if _, err := s.run.Run(ctx, argv[0], argv[1:]...); err != nil {
			return err
		}
	}
	return nil
}
