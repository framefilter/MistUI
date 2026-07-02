package httpapi

// Live portal-mode verification — needs both MISTUI_E2E_BASE and
// MISTUI_E2E_SSH (e.g. root@192.168.1.1). The ssh side installs a
// temporary rule blocking the router's own port-80 egress, which is what
// makes the probe read "not online" long enough to observe the paused
// state; removing it lets the watch see real connectivity and restore.
// MUTATES ROUTER STATE (kill switch, dnsmasq, firewall) — scratch
// instance only, restore config afterwards.

import (
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"testing"
	"time"
)

func e2eSSH(t *testing.T, target, script string) {
	t.Helper()
	out, err := exec.Command("ssh", target, script).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh %q: %v: %s", script, err, out)
	}
}

func TestLivePortalMode(t *testing.T) {
	base := os.Getenv("MISTUI_E2E_BASE")
	sshTarget := os.Getenv("MISTUI_E2E_SSH")
	if base == "" || sshTarget == "" {
		t.Skip("MISTUI_E2E_BASE or MISTUI_E2E_SSH not set")
	}
	origin := os.Getenv("MISTUI_E2E_ORIGIN")
	if origin == "" {
		origin = base
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: e2eTransport(t, base)}

	res, err := c.Get(base + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	var health struct{ OK, Provisioned bool }
	if err := jsonDecode(res, &health); err != nil || !health.OK || health.Provisioned {
		t.Fatalf("need a fresh scratch instance: %v %+v", err, health)
	}
	f := newFakeAuthenticator(t)
	f.origin = origin
	register(t, c, base, f)
	leaveSafe(t, c, base)

	// Posture: encrypted DNS on (the AP default) and kill switch on.
	if code, _ := post(t, c, base+"/api/wifi/ap", map[string]string{
		"ssid": "MistE2E", "key": "teste2epass123",
	}); code != http.StatusOK {
		t.Fatal("wifi/ap failed")
	}
	if code, _ := post(t, c, base+"/api/vpn/killswitch", map[string]bool{"enabled": true}); code != http.StatusOK {
		t.Fatal("killswitch on failed")
	}

	getBool := func(path, field string) bool {
		t.Helper()
		res, err := c.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		if err := jsonDecode(res, &out); err != nil {
			t.Fatal(err)
		}
		v, _ := out[field].(bool)
		return v
	}
	portal := func() map[string]any {
		t.Helper()
		res, err := c.Get(base + "/api/net/portal")
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		if err := jsonDecode(res, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Blind the probe (router port-80 egress) so the pause holds still.
	e2eSSH(t, sshTarget, `uci set firewall.mistui_e2e80=rule
uci set firewall.mistui_e2e80.name=mistui-e2e-block80
uci set firewall.mistui_e2e80.dest=wan
uci set firewall.mistui_e2e80.proto=tcp
uci set firewall.mistui_e2e80.dest_port=80
uci set firewall.mistui_e2e80.target=REJECT
uci commit firewall; /etc/init.d/firewall reload`)
	defer e2eSSH(t, sshTarget, `uci -q delete firewall.mistui_e2e80; uci commit firewall; /etc/init.d/firewall reload`)

	if code, _ := post(t, c, base+"/api/net/portal-mode", map[string]bool{"active": true}); code != http.StatusOK {
		t.Fatal("pause failed")
	}
	time.Sleep(3 * time.Second) // let uci/dnsmasq settle

	if getBool("/api/vpn/killswitch", "enabled") {
		t.Fatal("pause left the kill switch on")
	}
	if getBool("/api/dns", "enabled") {
		t.Fatal("pause left encrypted DNS on")
	}
	pause, _ := portal()["pause"].(map[string]any)
	if pause == nil || pause["savedKS"] != true || pause["savedDNS"] != true {
		t.Fatalf("pause state = %v", pause)
	}
	t.Log("paused: kill switch and encrypted DNS relaxed, posture saved")

	// "Sign in" = give the router its connectivity back.
	e2eSSH(t, sshTarget, `uci -q delete firewall.mistui_e2e80; uci commit firewall; /etc/init.d/firewall reload`)

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		out := portal()
		if out["pause"] == nil {
			if !getBool("/api/vpn/killswitch", "enabled") {
				t.Fatal("restore did not re-engage the kill switch")
			}
			if !getBool("/api/dns", "enabled") {
				t.Fatal("restore did not re-enable encrypted DNS")
			}
			t.Logf("auto-restored: %v", out["note"])
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatal("watch never restored after connectivity returned")
}
