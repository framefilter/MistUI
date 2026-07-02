package httpapi

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/framefilter/mistui/internal/dns"
	"github.com/framefilter/mistui/internal/netcfg"
	"github.com/framefilter/mistui/internal/store"
	"github.com/framefilter/mistui/internal/vpn"
)

// sessionHarness builds a server with a handle to its store, so tests can
// age sessions directly instead of waiting out real timeouts.
func sessionHarness(t *testing.T) (*httptest.Server, *http.Client, *store.Store, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st, vpn.NewUCIConnector(), netcfg.NewWiFi(), dns.NewService(dns.NewForwarder(dns.ListenAddr)), testRP, []string{testOrigin})
	ts := httptest.NewServer(srv.api)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	register(t, c, ts.URL, newFakeAuthenticator(t)) // establishes a session
	u, _ := url.Parse(ts.URL)
	var tok string
	for _, ck := range jar.Cookies(u) {
		if ck.Name == sessionCookie {
			tok = ck.Value
		}
	}
	if tok == "" {
		t.Fatal("no session cookie after registration")
	}
	return ts, c, st, tok
}

// getGated hits a session-gated, side-effect-free endpoint.
func getGated(t *testing.T, c *http.Client, base string) int {
	t.Helper()
	res, err := c.Get(base + "/api/privacy/mac-schedule")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestSessionIdleTimeout(t *testing.T) {
	ts, c, st, tok := sessionHarness(t)
	if code := getGated(t, c, ts.URL); code != http.StatusOK {
		t.Fatalf("fresh session: %d", code)
	}
	// Age last-seen past the idle window; issued stays recent.
	now := time.Now()
	_ = st.PutSession(tok, now, now.Add(-(sessionIdle + time.Minute)))
	if code := getGated(t, c, ts.URL); code != http.StatusUnauthorized {
		t.Fatalf("idle-expired session: %d, want 401", code)
	}
	// Expired tokens are cleaned up as they're seen.
	if _, _, ok, _ := st.Session(tok); ok {
		t.Error("expired session not deleted")
	}
}

func TestSessionAbsoluteCap(t *testing.T) {
	ts, c, st, tok := sessionHarness(t)
	now := time.Now()
	// Active (seen just now) but issued beyond the absolute cap.
	_ = st.PutSession(tok, now.Add(-(sessionAbsolute + time.Minute)), now)
	if code := getGated(t, c, ts.URL); code != http.StatusUnauthorized {
		t.Fatalf("absolute-capped session: %d, want 401", code)
	}
}

func TestSessionSlides(t *testing.T) {
	ts, c, st, tok := sessionHarness(t)
	now := time.Now()
	// Idle by 2 minutes — still valid, and a real request should slide it.
	_ = st.PutSession(tok, now.Add(-time.Hour), now.Add(-2*time.Minute))
	if code := getGated(t, c, ts.URL); code != http.StatusOK {
		t.Fatalf("session within idle window: %d", code)
	}
	_, seen, ok, _ := st.Session(tok)
	if !ok || time.Since(seen) > time.Minute {
		t.Errorf("last-seen not slid forward: seen=%v ok=%v", seen, ok)
	}
}

func TestLogoutRevokes(t *testing.T) {
	ts, c, st, tok := sessionHarness(t)
	res, err := c.Post(ts.URL+"/api/logout", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if _, _, ok, _ := st.Session(tok); ok {
		t.Error("logout did not delete the session server-side")
	}
	if code := getGated(t, c, ts.URL); code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d, want 401", code)
	}
}
