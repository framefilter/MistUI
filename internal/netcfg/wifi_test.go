package netcfg

import (
	"context"
	"strings"
	"testing"
	"time"
)

// scriptedRunner records commands and returns canned output by substring.
type scriptedRunner struct {
	cmds    []string
	replies map[string]string // first substring match wins
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	full := name + " " + strings.Join(args, " ")
	r.cmds = append(r.cmds, full)
	for k, v := range r.replies {
		if strings.Contains(full, k) {
			return v, nil
		}
	}
	return "", nil
}

func (r *scriptedRunner) all() string { return strings.Join(r.cmds, "\n") }

func TestSetAP(t *testing.T) {
	rec := &scriptedRunner{}
	w := NewWiFiWithRunner(rec)
	if err := w.SetAP(context.Background(), "MistTravel", "hunter2boogaloo"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wireless.radio0.disabled=0",
		"wireless.mistui_ap=wifi-iface",
		"wireless.mistui_ap.mode=ap",
		"wireless.mistui_ap.ssid=MistTravel",
		"wireless.mistui_ap.encryption=psk2",
		"wireless.mistui_ap.key=hunter2boogaloo",
		"uci commit wireless",
		"wifi reload",
	} {
		if !strings.Contains(rec.all(), want) {
			t.Errorf("missing %q", want)
		}
	}

	// Validation: bad PSK and bad SSID must never reach the runner.
	if err := w.SetAP(context.Background(), "x", "short"); err == nil {
		t.Error("short key accepted")
	}
	if err := w.SetAP(context.Background(), "", "longenoughkey"); err == nil {
		t.Error("empty SSID accepted")
	}
}

func TestJoinUplink(t *testing.T) {
	rec := &scriptedRunner{}
	w := NewWiFiWithRunner(rec)
	ident := &Identity{MAC: "3c:15:c2:aa:bb:cc", Hostname: "iPhone", Profile: "apple"}
	if err := w.JoinUplink(context.Background(), "HotelGuest", "", ident); err != nil {
		t.Fatal(err)
	}
	all := rec.all()
	for _, want := range []string{
		"wireless.mistui_sta.mode=sta",
		"wireless.mistui_sta.network=wwan",
		"wireless.mistui_sta.ssid=HotelGuest",
		"wireless.mistui_sta.encryption=none",
		"wireless.mistui_sta.macaddr=3c:15:c2:aa:bb:cc", // set before association
		"network.wwan.hostname=iPhone",                  // matching DHCP hostname
		"network.wwan.proto=dhcp",
		"uci add_list firewall.$zone.network=wwan",
		"/etc/init.d/network reload",
		"wifi reload",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(all, "mistui_sta.key=") && !strings.Contains(all, "delete wireless.mistui_sta.key") {
		t.Error("open network must not set a key")
	}

	// Secured join, no identity: psk2 + key, and MAC/hostname overrides cleared.
	rec2 := &scriptedRunner{}
	if err := NewWiFiWithRunner(rec2).JoinUplink(context.Background(), "CaféWLAN", "espresso99", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec2.all(), "encryption=psk2") || !strings.Contains(rec2.all(), "key=espresso99") {
		t.Error("secured join missing psk2/key")
	}
	if !strings.Contains(rec2.all(), "delete wireless.mistui_sta.macaddr") {
		t.Error("nil identity should clear the MAC override")
	}
	if !strings.Contains(rec2.all(), "delete network.wwan.hostname") {
		t.Error("nil identity should clear the hostname override")
	}
}

func TestScanParsesUbus(t *testing.T) {
	rec := &scriptedRunner{replies: map[string]string{
		"network.wireless status": `{"radio0":{"up":true,"interfaces":[{"ifname":"phy0-ap0"}]}}`,
		"iwinfo scan": `{"results":[
			{"ssid":"HotelGuest","signal":-55,"encryption":{"enabled":false}},
			{"ssid":"HotelGuest","signal":-70,"encryption":{"enabled":false}},
			{"ssid":"CaféWLAN","signal":-48,"encryption":{"enabled":true}},
			{"ssid":"","signal":-30,"encryption":{"enabled":false}}]}`,
	}}
	nets, err := NewWiFiWithRunner(rec).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 {
		t.Fatalf("want 2 networks (deduped, hidden dropped), got %v", nets)
	}
	if nets[1].SSID != "CaféWLAN" || nets[1].Encryption != "psk" {
		t.Fatalf("unexpected second network: %+v", nets[1])
	}
}

func TestScanRequiresUpRadio(t *testing.T) {
	rec := &scriptedRunner{replies: map[string]string{
		"network.wireless status": `{"radio0":{"up":false,"interfaces":[]}}`,
	}}
	// Short deadline: Scan retries radio bring-up for ~10 s in production,
	// which the test does not need to sit through.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := NewWiFiWithRunner(rec).Scan(ctx); err == nil {
		t.Fatal("scan with radio down should error")
	}
}

func TestApplySTAIdentity(t *testing.T) {
	rec := &scriptedRunner{}
	ident := Identity{MAC: "5c:0a:5b:11:22:33", Hostname: "Galaxy-S23", Profile: "samsung"}
	if err := NewWiFiWithRunner(rec).ApplySTAIdentity(context.Background(), ident); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wireless.mistui_sta.macaddr=5c:0a:5b:11:22:33",
		"network.wwan.hostname=Galaxy-S23",
		"wifi reload",
	} {
		if !strings.Contains(rec.all(), want) {
			t.Errorf("missing %q", want)
		}
	}

	// Generic identity (no hostname) clears the hostname override.
	rec2 := &scriptedRunner{}
	gen := Identity{MAC: "02:aa:bb:cc:dd:ee", Profile: "generic"}
	if err := NewWiFiWithRunner(rec2).ApplySTAIdentity(context.Background(), gen); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec2.all(), "delete network.wwan.hostname") {
		t.Error("generic identity should clear the hostname override")
	}
}
