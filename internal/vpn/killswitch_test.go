package vpn

import (
	"context"
	"strings"
	"testing"
)

type cannedRunner struct {
	cmds  []string
	reply string
}

func (r *cannedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	return r.reply, nil
}

func TestKillSwitchCommands(t *testing.T) {
	rec := &cannedRunner{}
	c := NewUCIConnectorWithRunner(rec)

	if err := c.SetKillSwitch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	on := rec.cmds[len(rec.cmds)-1]
	if !strings.Contains(on, "uci delete firewall.$found") || !strings.Contains(on, `dest)" = "wan"`) {
		t.Errorf("enable script doesn't remove lan→wan forwarding: %q", on)
	}

	if err := c.SetKillSwitch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	off := rec.cmds[len(rec.cmds)-1]
	if !strings.Contains(off, "uci add firewall forwarding") || !strings.Contains(off, "dest=wan") {
		t.Errorf("disable script doesn't restore lan→wan forwarding: %q", off)
	}
}

func TestKillSwitchFlushesConntrack(t *testing.T) {
	flushes := 0
	c := UCIConnector{run: &cannedRunner{}, flushCT: func() error { flushes++; return nil }}
	if err := c.SetKillSwitch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if flushes != 1 {
		t.Errorf("enable: %d conntrack flushes, want 1 (established flows bypass fw4 rules)", flushes)
	}
	if err := c.SetKillSwitch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if flushes != 1 {
		t.Errorf("disable must not flush (nothing newly blocked); got %d total", flushes)
	}
}

func TestKillSwitchState(t *testing.T) {
	for reply, want := range map[string]bool{"on": true, "off": false} {
		c := NewUCIConnectorWithRunner(&cannedRunner{reply: reply})
		got, err := c.KillSwitch(context.Background())
		if err != nil || got != want {
			t.Errorf("reply %q: got %v err %v, want %v", reply, got, err, want)
		}
	}
}

func TestImportCreatesVPNZone(t *testing.T) {
	cfg, err := ParseConfig(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	rec := &cannedRunner{}
	if err := NewUCIConnectorWithRunner(rec).Import(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rec.cmds, "\n")
	for _, want := range []string{
		"firewall.@zone[-1].name=vpn",
		"add_list firewall.@zone[-1].network=wg0",
		"firewall.@zone[-1].masq=1",
		"firewall.@forwarding[-1].src=lan",
		"firewall.@forwarding[-1].dest=vpn",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in vpn zone setup", want)
		}
	}
}
