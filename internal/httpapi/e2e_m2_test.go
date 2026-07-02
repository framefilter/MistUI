package httpapi

// Live M2 verification — same opt-in mechanism as TestLiveEndToEnd, same
// caveats, plus one more: this MUTATES WIRELESS AND FIREWALL STATE on the
// target (creates a "MistE2E" AP, toggles the kill switch). Run against a
// scratch instance on a dev router only, and clean up afterwards.

import (
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"
)

func TestLiveM2Network(t *testing.T) {
	base := os.Getenv("MISTUI_E2E_BASE")
	if base == "" {
		t.Skip("MISTUI_E2E_BASE not set")
	}
	origin := os.Getenv("MISTUI_E2E_ORIGIN")
	if origin == "" {
		origin = base
	}
	transport := e2eTransport(t, base)

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: transport}

	res, err := c.Get(base + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	var health struct{ OK, Provisioned bool }
	if err := jsonDecode(res, &health); err != nil || !health.OK {
		t.Fatalf("health: %v %+v", err, health)
	}
	if health.Provisioned {
		t.Fatal("target already provisioned; use a fresh scratch instance")
	}

	f := newFakeAuthenticator(t)
	f.origin = origin
	register(t, c, base, f)

	// Travel AP — enables the radio, prerequisite for scanning.
	code, body := post(t, c, base+"/api/wifi/ap", map[string]string{
		"ssid": "MistE2E", "key": "teste2epass123",
	})
	if code != http.StatusOK {
		t.Fatalf("wifi/ap: %d %v", code, body)
	}
	res, err = c.Get(base + "/api/wifi/status")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		APSSID    string `json:"apSsid"`
		APEnabled bool   `json:"apEnabled"`
	}
	if err := jsonDecode(res, &st); err != nil || !st.APEnabled || st.APSSID != "MistE2E" {
		t.Fatalf("wifi/status after ap: %v %+v", err, st)
	}

	// Scan from the now-up radio. Result count depends on the RF
	// neighborhood, so assert success, not contents.
	code, scan := post(t, c, base+"/api/wifi/scan", nil)
	if code != http.StatusOK {
		t.Fatalf("wifi/scan: %d %v", code, scan)
	}
	nets, _ := scan["networks"].([]any)
	t.Logf("scan saw %d networks", len(nets))

	// Portal probe: the dev router has a working wired uplink.
	res, err = c.Get(base + "/api/net/portal")
	if err != nil {
		t.Fatal(err)
	}
	var portal struct{ Online, Captive bool }
	if err := jsonDecode(res, &portal); err != nil || !portal.Online || portal.Captive {
		t.Fatalf("portal probe on a working uplink: %v %+v", err, portal)
	}

	// Kill switch round-trip.
	for _, want := range []bool{true, false} {
		if code, body := post(t, c, base+"/api/vpn/killswitch", map[string]bool{"enabled": want}); code != http.StatusOK {
			t.Fatalf("killswitch set %v: %d %v", want, code, body)
		}
		res, err = c.Get(base + "/api/vpn/killswitch")
		if err != nil {
			t.Fatal(err)
		}
		var ks struct{ Enabled bool }
		if err := jsonDecode(res, &ks); err != nil || ks.Enabled != want {
			t.Fatalf("killswitch readback: %v got %v want %v", err, ks.Enabled, want)
		}
	}

	// MAC schedule round-trip + default.
	res, _ = c.Get(base + "/api/privacy/mac-schedule")
	var mode struct{ Mode string }
	if err := jsonDecode(res, &mode); err != nil || mode.Mode != "on-join" {
		t.Fatalf("default mac schedule: %v %+v", err, mode)
	}
	if code, _ := post(t, c, base+"/api/privacy/mac-schedule", map[string]string{"mode": "daily"}); code != http.StatusOK {
		t.Fatal("set daily failed")
	}
	if code, _ := post(t, c, base+"/api/privacy/mac-schedule", map[string]string{"mode": "sometimes"}); code != http.StatusBadRequest {
		t.Fatal("bogus mode accepted")
	}

	// Roll-MAC with no uplink configured must refuse cleanly.
	if code, _ := post(t, c, base+"/api/privacy/roll-mac", nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("roll-mac without uplink: want 422")
	}
	t.Logf("live M2 OK against %s", base)
}
