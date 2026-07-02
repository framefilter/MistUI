package dns

import (
	"context"
	"strings"
	"testing"
)

type recorder struct {
	cmds  []string
	reply string
}

func (r *recorder) Run(_ context.Context, name string, args ...string) (string, error) {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	return r.reply, nil
}

func newRecordedService(reply string) (*Service, *recorder) {
	rec := &recorder{reply: reply}
	return NewServiceWithRunner(NewForwarder(ListenAddr), rec), rec
}

func TestEnableCommands(t *testing.T) {
	s, rec := newRecordedService("")
	if err := s.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rec.cmds, "\n")
	for _, want := range []string{
		"dhcp.@dnsmasq[0].noresolv=1",
		"add_list dhcp.@dnsmasq[0].server=127.0.0.1#5335",
		// The OUTPUT-side rule must have no src (that is what makes it
		// OUTPUT in fw4) and must reject port 53 toward wan.
		"firewall.mistui_dns_out.dest=wan",
		"firewall.mistui_dns_out.dest_port=53",
		"firewall.mistui_dns_out.target=REJECT",
		"firewall.mistui_dns_fwd.src=lan",
		"firewall.mistui_dns_hijack=redirect",
		"firewall.mistui_dns_hijack.src_dport=53",
		"firewall.mistui_dns_hijack.target=DNAT",
		"/etc/init.d/dnsmasq restart",
		"/etc/init.d/firewall reload",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("enable: missing %q", want)
		}
	}
	if strings.Contains(all, "mistui_dns_out.src=") {
		t.Error("enable: OUTPUT rule must not have a src zone")
	}
}

func TestDisableCommands(t *testing.T) {
	s, rec := newRecordedService("")
	if err := s.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rec.cmds, "\n")
	for _, want := range []string{
		"delete dhcp.@dnsmasq[0].noresolv",
		"del_list 'dhcp.@dnsmasq[0].server=127.0.0.1#5335'",
		"delete firewall.mistui_dns_out",
		"delete firewall.mistui_dns_fwd",
		"delete firewall.mistui_dns_hijack",
		"delete firewall.mistui_dns_ks",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("disable: missing %q", want)
		}
	}
}

func TestEnabled(t *testing.T) {
	for reply, want := range map[string]bool{"on": true, "off": false} {
		s, _ := newRecordedService(reply)
		got, err := s.Enabled(context.Background())
		if err != nil || got != want {
			t.Errorf("reply %q: got %v err %v, want %v", reply, got, err, want)
		}
	}
}

func TestSetFailClosed(t *testing.T) {
	s, rec := newRecordedService("")
	if err := s.SetFailClosed(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rec.cmds, "\n")
	for _, want := range []string{
		"firewall.mistui_dns_ks=rule",
		"firewall.mistui_dns_ks.dest=wan",
		"firewall.mistui_dns_ks.dest_port=443",
		"firewall.mistui_dns_ks.target=REJECT",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("fail-closed on: missing %q", want)
		}
	}
	// Every curated resolver address must be in the deny-list, so a
	// provider switch can never dodge the rule.
	for _, ip := range AllResolverIPs() {
		if !strings.Contains(all, "dest_ip="+ip) {
			t.Errorf("fail-closed on: missing resolver IP %s", ip)
		}
	}
	if strings.Contains(all, "mistui_dns_ks.src=") {
		t.Error("fail-closed rule must not have a src zone (must be OUTPUT)")
	}

	s2, rec2 := newRecordedService("")
	if err := s2.SetFailClosed(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	off := strings.Join(rec2.cmds, "\n")
	if !strings.Contains(off, "delete firewall.mistui_dns_ks") {
		t.Errorf("fail-closed off: rule not removed: %q", off)
	}
}
