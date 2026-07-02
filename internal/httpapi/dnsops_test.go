package httpapi

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/framefilter/mistui/internal/dns"
	"github.com/framefilter/mistui/internal/maint"
	"github.com/framefilter/mistui/internal/netcfg"
	"github.com/framefilter/mistui/internal/store"
	"github.com/framefilter/mistui/internal/vpn"
)

type cmdRecorder struct {
	cmds  []string
	reply string
}

func (r *cmdRecorder) Run(_ context.Context, name string, args ...string) (string, error) {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	return r.reply, nil
}

func (r *cmdRecorder) all() string { return strings.Join(r.cmds, "\n") }

// newDNSHarness builds an authenticated client against a server whose vpn,
// wifi, and dns commands run through recorders. reply is what every
// recorded command "prints" — "on"/"off" drives the KillSwitch() and
// Enabled() state checks.
func newDNSHarness(t *testing.T, reply string) (*httptest.Server, *http.Client, *cmdRecorder, *cmdRecorder) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	vpnRec := &cmdRecorder{reply: reply}
	dnsRec := &cmdRecorder{reply: reply}
	wifiRec := &cmdRecorder{}
	srv := New(st,
		vpn.NewUCIConnectorWithRunner(vpnRec),
		netcfg.NewWiFiWithRunner(wifiRec),
		dns.NewServiceWithRunner(dns.NewForwarder(dns.ListenAddr), dnsRec),
		maint.NewService(),
		testRP, []string{testOrigin})
	ts := httptest.NewServer(srv.api)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	register(t, c, ts.URL, newFakeAuthenticator(t))
	return ts, c, dnsRec, vpnRec
}

func TestKillSwitchTogglesFailClosed(t *testing.T) {
	// dnsReply "on": the kill-switch handler's Enabled() check sees
	// encrypted DNS as active, and KillSwitch() state reads as on.
	ts, c, dnsRec, _ := newDNSHarness(t, "on")

	if code, _ := post(t, c, ts.URL+"/api/vpn/killswitch", map[string]bool{"enabled": true}); code != http.StatusOK {
		t.Fatalf("killswitch on: %d", code)
	}
	if !strings.Contains(dnsRec.all(), "firewall.mistui_dns_ks=rule") {
		t.Error("kill switch on did not install the DNS fail-closed rule")
	}

	dnsRec.cmds = nil
	if code, _ := post(t, c, ts.URL+"/api/vpn/killswitch", map[string]bool{"enabled": false}); code != http.StatusOK {
		t.Fatalf("killswitch off: %d", code)
	}
	if !strings.Contains(dnsRec.all(), "delete firewall.mistui_dns_ks") {
		t.Error("kill switch off did not remove the DNS fail-closed rule")
	}
}

func TestAPSetupAppliesDNSDefaultOnce(t *testing.T) {
	ts, c, dnsRec, _ := newDNSHarness(t, "off")

	body := map[string]string{"ssid": "mist-travel", "key": "supersecret"}
	if code, _ := post(t, c, ts.URL+"/api/wifi/ap", body); code != http.StatusOK {
		t.Fatalf("wifi/ap: %d", code)
	}
	if !strings.Contains(dnsRec.all(), "dhcp.@dnsmasq[0].noresolv=1") {
		t.Fatal("first AP setup did not enable encrypted DNS by default")
	}

	// A second AP change must not re-apply the default…
	dnsRec.cmds = nil
	if code, _ := post(t, c, ts.URL+"/api/wifi/ap", body); code != http.StatusOK {
		t.Fatalf("wifi/ap again: %d", code)
	}
	if strings.Contains(dnsRec.all(), "noresolv=1") {
		t.Error("AP setup re-applied the DNS default")
	}

	// …and neither may it after the user explicitly turns DNS off.
	if code, _ := post(t, c, ts.URL+"/api/dns", map[string]bool{"enabled": false}); code != http.StatusOK {
		t.Fatal("dns disable failed")
	}
	dnsRec.cmds = nil
	if code, _ := post(t, c, ts.URL+"/api/wifi/ap", body); code != http.StatusOK {
		t.Fatalf("wifi/ap after user opt-out: %d", code)
	}
	if strings.Contains(dnsRec.all(), "noresolv=1") {
		t.Error("AP setup overrode the user's explicit DNS opt-out")
	}
}
