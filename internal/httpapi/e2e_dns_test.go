package httpapi

// Live encrypted-DNS verification — same opt-in mechanism as the other live
// tests, same caveat as TestLiveM2Network dialed up: this MUTATES DHCP AND
// FIREWALL STATE on the target (repoints dnsmasq at the DoH forwarder,
// installs/removes the port-53 and fail-closed rules, toggles the kill
// switch, and briefly leaves the router without working DNS). Run against a
// scratch instance on a dev router only, snapshot /etc/config first, and
// restore afterwards.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"testing"
	"time"
)

// routerResolver returns a resolver that queries the target router's
// dnsmasq directly, plus a generator of guaranteed-uncached names — the
// only honest way to observe the router's live DNS path (dnsmasq caches,
// and warm HTTP connections survive firewall changes).
func routerResolver(t *testing.T, base string) (*net.Resolver, func() string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := net.LookupHost(u.Hostname())
	if err != nil || len(addrs) == 0 {
		t.Fatalf("cannot resolve router host %q: %v", u.Hostname(), err)
	}
	dnsAddr := net.JoinHostPort(addrs[0], "53")
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dnsAddr)
		},
	}
	freshName := func() string {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b) + ".mistui-e2e.example.com"
	}
	return r, freshName
}

// establishedFlow is a keep-alive HTTP connection through the router to a
// stable anycast site (1.1.1.1:80), opened before the kill switch so its
// conntrack entry predates the rule change.
type establishedFlow struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func newEstablishedFlow(t *testing.T) *establishedFlow {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "1.1.1.1:80", 5*time.Second)
	if err != nil {
		t.Fatalf("open pre-killswitch flow: %v", err)
	}
	f := &establishedFlow{t: t, conn: conn, br: bufio.NewReader(conn)}
	if !f.roundTrip(10 * time.Second) {
		t.Fatal("pre-killswitch flow: first request failed — no route to 1.1.1.1:80?")
	}
	return f
}

// roundTrip sends one keep-alive HTTP request and fully drains the reply.
func (f *establishedFlow) roundTrip(timeout time.Duration) bool {
	f.t.Helper()
	_ = f.conn.SetDeadline(time.Now().Add(timeout))
	if _, err := f.conn.Write([]byte("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n")); err != nil {
		return false
	}
	res, err := http.ReadResponse(f.br, nil)
	if err != nil {
		return false
	}
	_, err = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return err == nil
}

func (f *establishedFlow) stillWorks() bool { return f.roundTrip(6 * time.Second) }

func (f *establishedFlow) close() { f.conn.Close() }

func TestLiveDNS(t *testing.T) {
	base := os.Getenv("MISTUI_E2E_BASE")
	if base == "" {
		t.Skip("MISTUI_E2E_BASE not set")
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
	if err := jsonDecode(res, &health); err != nil || !health.OK {
		t.Fatalf("health: %v %+v", err, health)
	}
	if health.Provisioned {
		t.Fatal("target already provisioned; use a fresh scratch instance")
	}
	f := newFakeAuthenticator(t)
	f.origin = origin
	register(t, c, base, f)
	leaveSafe(t, c, base)

	type dnsView struct {
		Enabled   bool   `json:"enabled"`
		Provider  string `json:"provider"`
		Providers []struct{ Key, Label string }
		Stats     struct {
			Queries  uint64 `json:"queries"`
			Failures uint64 `json:"failures"`
			LastErr  string `json:"lastError"`
		}
	}
	getDNS := func() dnsView {
		t.Helper()
		res, err := c.Get(base + "/api/dns")
		if err != nil {
			t.Fatal(err)
		}
		var v dnsView
		if err := jsonDecode(res, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	probe := func() (online bool) {
		t.Helper()
		res, err := c.Get(base + "/api/net/portal")
		if err != nil {
			t.Fatal(err)
		}
		var p struct{ Online, Captive bool }
		if err := jsonDecode(res, &p); err != nil {
			t.Fatal(err)
		}
		return p.Online
	}

	// Fresh instance: off, curated defaults.
	if v := getDNS(); v.Enabled || v.Provider != "quad9" || len(v.Providers) != 3 {
		t.Fatalf("initial dns state: %+v", v)
	}

	// The wizard's AP step must switch encrypted DNS on by default.
	if code, body := post(t, c, base+"/api/wifi/ap", map[string]string{
		"ssid": "MistE2E", "key": "teste2epass123",
	}); code != http.StatusOK {
		t.Fatalf("wifi/ap: %d %v", code, body)
	}
	if v := getDNS(); !v.Enabled {
		t.Fatal("AP setup did not enable encrypted DNS by default")
	}

	// The portal probe resolves detectportal.firefox.com through the
	// router's resolver — now dnsmasq → forwarder → DoH. Online proves the
	// whole encrypted path works on this hardware.
	if !probe() {
		t.Fatalf("portal probe offline with encrypted DNS on: %+v", getDNS())
	}
	v := getDNS()
	if v.Stats.Queries == 0 {
		t.Fatalf("probe resolved but forwarder saw no queries — dnsmasq is not forwarding to it: %+v", v)
	}
	t.Logf("encrypted path live: %d queries, %d failures", v.Stats.Queries, v.Stats.Failures)

	// Live-path oracle: resolve fresh (never-cached) names through the
	// router's dnsmasq itself. NXDOMAIN means the encrypted path answered;
	// SERVFAIL/timeout means it is blocked.
	resolver, freshName := routerResolver(t, base)
	resolves := func() bool {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := resolver.LookupHost(ctx, freshName())
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true // NXDOMAIN: the upstream really answered
		}
		return err == nil
	}
	if !resolves() {
		t.Fatal("uncached lookup failed while encrypted DNS is on and unblocked")
	}

	// Open a flow through the router *before* the kill switch, and prove
	// the switch severs it: fw4 accepts established connections before
	// zone rules run, so without the conntrack flush this keep-alive
	// connection would keep working right through the closed switch.
	flow := newEstablishedFlow(t)
	defer flow.close()

	// Kill switch on ⇒ fail closed: no tunnel exists on the scratch
	// router, so new lookups must die (DoH rejected on the raw wan).
	if code, _ := post(t, c, base+"/api/vpn/killswitch", map[string]bool{"enabled": true}); code != http.StatusOK {
		t.Fatal("killswitch on failed")
	}
	time.Sleep(2 * time.Second) // let fw4 reload settle
	if resolves() {
		t.Fatal("kill switch on, tunnel down — uncached name still resolves: DNS did not fail closed")
	}
	if getDNS().Stats.Failures == 0 {
		t.Fatal("fail-closed lookup produced no forwarder failure — did the query reach the forwarder?")
	}
	if flow.stillWorks() {
		t.Fatal("pre-existing connection survived the kill switch — conntrack was not flushed")
	}

	// Kill switch off ⇒ DoH may use the wan again.
	if code, _ := post(t, c, base+"/api/vpn/killswitch", map[string]bool{"enabled": false}); code != http.StatusOK {
		t.Fatal("killswitch off failed")
	}
	time.Sleep(2 * time.Second)
	if !resolves() {
		t.Fatal("kill switch off but DNS still dead")
	}

	// Provider switch round-trip, and the new upstream actually answers.
	if code, _ := post(t, c, base+"/api/dns/provider", map[string]string{"provider": "cloudflare"}); code != http.StatusOK {
		t.Fatal("provider switch failed")
	}
	if v := getDNS(); v.Provider != "cloudflare" {
		t.Fatalf("provider readback: %+v", v)
	}
	if !resolves() {
		t.Fatal("uncached lookup failed after provider switch")
	}
	if code, _ := post(t, c, base+"/api/dns/provider", map[string]string{"provider": "dns.evil"}); code != http.StatusBadRequest {
		t.Fatal("bogus provider accepted")
	}

	// Explicit disable restores plain DNS (and the honest leak warning).
	if code, _ := post(t, c, base+"/api/dns", map[string]bool{"enabled": false}); code != http.StatusOK {
		t.Fatal("dns disable failed")
	}
	if v := getDNS(); v.Enabled {
		t.Fatal("disable did not stick")
	}
	time.Sleep(2 * time.Second)
	if !resolves() {
		t.Fatal("plain DNS did not come back after disable")
	}
	t.Logf("live DNS OK against %s", base)
}
