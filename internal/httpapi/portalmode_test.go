package httpapi

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/framefilter/mistui/internal/dns"
	"github.com/framefilter/mistui/internal/maint"
	"github.com/framefilter/mistui/internal/netcfg"
	"github.com/framefilter/mistui/internal/store"
	"github.com/framefilter/mistui/internal/vpn"
)

// portalHarness: authenticated client + server internals, with recorded
// vpn/dns commands and a swappable probe verdict.
type portalHarness struct {
	ts       *httptest.Server
	c        *http.Client
	srv      *Server
	vpnRec   *cmdRecorder
	dnsRec   *cmdRecorder
	veredict atomic.Value // netcfg.PortalStatus
}

func newPortalHarness(t *testing.T, reply string) *portalHarness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &portalHarness{
		vpnRec: &cmdRecorder{reply: reply},
		dnsRec: &cmdRecorder{reply: reply},
	}
	h.srv = New(st,
		vpn.NewUCIConnectorWithRunner(h.vpnRec),
		netcfg.NewWiFiWithRunner(&cmdRecorder{}),
		dns.NewServiceWithRunner(dns.NewForwarder(dns.ListenAddr), h.dnsRec),
		maint.NewService(),
		testRP, []string{testOrigin})
	h.veredict.Store(netcfg.PortalStatus{}) // offline by default
	h.srv.probe = func(context.Context) netcfg.PortalStatus {
		return h.veredict.Load().(netcfg.PortalStatus)
	}
	h.ts = httptest.NewServer(h.srv.api)
	t.Cleanup(h.ts.Close)
	jar, _ := cookiejar.New(nil)
	h.c = &http.Client{Jar: jar}
	register(t, h.c, h.ts.URL, newFakeAuthenticator(t))
	return h
}

func fastPortalTimers(t *testing.T) {
	t.Helper()
	ow, op, os_, oe := portalWindow, portalProbeEvery, portalScoutFor, portalScoutEvery
	portalWindow, portalProbeEvery = 2*time.Second, 50*time.Millisecond
	portalScoutFor, portalScoutEvery = time.Second, 50*time.Millisecond
	t.Cleanup(func() {
		portalWindow, portalProbeEvery, portalScoutFor, portalScoutEvery = ow, op, os_, oe
	})
}

func portalPause(t *testing.T, h *portalHarness) map[string]any {
	t.Helper()
	res, err := h.c.Get(h.ts.URL + "/api/net/portal")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := jsonDecode(res, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPortalPauseRelaxesAndRestores(t *testing.T) {
	h := newPortalHarness(t, "on") // kill switch on, encrypted DNS on

	if code, _ := post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": true}); code != http.StatusOK {
		t.Fatal("pause failed")
	}
	vpnAll := strings.Join(h.vpnRec.cmds, "\n")
	if !strings.Contains(vpnAll, "ifdown wg0") {
		t.Error("pause did not hold the tunnel down")
	}
	if !strings.Contains(vpnAll, "uci add firewall forwarding") {
		t.Error("pause did not relax the kill switch (lan→wan restore missing)")
	}
	if !strings.Contains(strings.Join(h.dnsRec.cmds, "\n"), "delete dhcp.@dnsmasq[0].noresolv") {
		t.Error("pause did not relax encrypted DNS")
	}
	pause, _ := portalPause(t, h)["pause"].(map[string]any)
	if pause == nil || pause["active"] != true || pause["savedKS"] != true || pause["savedDNS"] != true {
		t.Fatalf("pause state = %v", pause)
	}

	h.vpnRec.cmds, h.dnsRec.cmds = nil, nil
	if code, _ := post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": false}); code != http.StatusOK {
		t.Fatal("restore failed")
	}
	vpnAll = strings.Join(h.vpnRec.cmds, "\n")
	if !strings.Contains(vpnAll, "uci delete firewall.$found") {
		t.Error("restore did not re-engage the kill switch")
	}
	if strings.Contains(vpnAll, "ifup wg0") {
		t.Error("restore brought up a VPN that was never configured")
	}
	dnsAll := strings.Join(h.dnsRec.cmds, "\n")
	if !strings.Contains(dnsAll, "dhcp.@dnsmasq[0].noresolv=1") || !strings.Contains(dnsAll, "firewall.mistui_dns_ks=rule") {
		t.Error("restore did not re-enable encrypted DNS + fail-closed")
	}
	out := portalPause(t, h)
	if out["pause"] != nil {
		t.Error("pause record survived the restore")
	}
	if note, _ := out["note"].(string); !strings.Contains(note, "restored") {
		t.Errorf("note = %q", note)
	}
}

func TestPortalPauseOnlyRelaxesWhatWasOn(t *testing.T) {
	h := newPortalHarness(t, "off") // kill switch off, encrypted DNS off
	if code, _ := post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": true}); code != http.StatusOK {
		t.Fatal("pause failed")
	}
	if strings.Contains(strings.Join(h.vpnRec.cmds, "\n"), "uci add firewall forwarding") {
		t.Error("pause touched a kill switch that was already off")
	}
	if strings.Contains(strings.Join(h.dnsRec.cmds, "\n"), "delete dhcp.@dnsmasq[0].noresolv") {
		t.Error("pause touched encrypted DNS that was already off")
	}
}

func TestPortalReEnterPreservesSavedPosture(t *testing.T) {
	h := newPortalHarness(t, "on")
	post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": true})
	// While paused the live state reads "off"; re-entering must not adopt
	// the relaxed state as the posture to restore.
	h.vpnRec.reply, h.dnsRec.reply = "off", "off"
	post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": true})
	pause, _ := portalPause(t, h)["pause"].(map[string]any)
	if pause == nil || pause["savedKS"] != true || pause["savedDNS"] != true {
		t.Fatalf("re-enter clobbered saved posture: %v", pause)
	}
}

func TestPortalWatchAutoRestoresWhenOnline(t *testing.T) {
	fastPortalTimers(t)
	h := newPortalHarness(t, "on")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.srv.RunPortalWatch(ctx)

	h.veredict.Store(netcfg.PortalStatus{Captive: true, PortalURL: "http://portal.example/login"})
	if code, _ := post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": true}); code != http.StatusOK {
		t.Fatal("pause failed")
	}
	h.veredict.Store(netcfg.PortalStatus{Online: true}) // user signed in
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.portalRecord() == nil {
			if !strings.Contains(strings.Join(h.vpnRec.cmds, "\n"), "uci delete firewall.$found") {
				t.Fatal("auto-restore did not re-engage the kill switch")
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("watch never restored after the portal cleared")
}

func TestPortalWatchExpiresTheWindow(t *testing.T) {
	fastPortalTimers(t)
	h := newPortalHarness(t, "on")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.srv.RunPortalWatch(ctx)

	h.veredict.Store(netcfg.PortalStatus{Captive: true}) // never clears
	post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": true})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.srv.portalRecord() == nil {
			out := portalPause(t, h)
			if note, _ := out["note"].(string); !strings.Contains(note, "expired") {
				t.Fatalf("note after expiry = %q", note)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("pause never expired")
}

func TestPortalScoutEntersOnCaptiveJoin(t *testing.T) {
	fastPortalTimers(t)
	h := newPortalHarness(t, "on")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.srv.RunPortalWatch(ctx)

	h.veredict.Store(netcfg.PortalStatus{Captive: true, PortalURL: "http://hotel.example/auth"})
	h.srv.kickPortalWatch() // what wifiJoinUplink does
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rec := h.srv.portalRecord(); rec != nil {
			if rec.PortalURL != "http://hotel.example/auth" {
				t.Fatalf("portal URL = %q", rec.PortalURL)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("scout never entered portal mode on a captive join")
}

func TestManualToggleCancelsPause(t *testing.T) {
	h := newPortalHarness(t, "on")
	post(t, h.c, h.ts.URL+"/api/net/portal-mode", map[string]bool{"active": true})
	if code, _ := post(t, h.c, h.ts.URL+"/api/vpn/killswitch", map[string]bool{"enabled": true}); code != http.StatusOK {
		t.Fatal("killswitch set failed")
	}
	if h.srv.portalRecord() != nil {
		t.Fatal("manual kill-switch change did not cancel the pause")
	}
	if note, _ := portalPause(t, h)["note"].(string); !strings.Contains(note, "canceled") {
		t.Fatalf("note = %q", note)
	}
}
