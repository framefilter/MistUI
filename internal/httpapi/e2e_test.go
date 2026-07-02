package httpapi

// Opt-in end-to-end test against a LIVE mistd — typically a scratch
// instance on the dev router. It provisions the instance (so the target
// must be FRESH/unprovisioned), logs in, and imports a dummy WireGuard
// config, which WRITES REAL UCI STATE on the target device.
//
//	MISTUI_E2E_BASE=https://mist.lan:9443 \
//	go test ./internal/httpapi -run TestLiveEndToEnd -v
//
// The base should be https and use the RP hostname: session cookies are
// Secure (the jar won't send them over plain http), and this exercises the
// device-CA TLS path — the test bootstraps trust from the target's own
// /ca.pem. The dummy config routes only 10.99.88.0/24 so bringing the
// (dead) tunnel up never hijacks the router's default route.

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

func e2eKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestLiveEndToEnd(t *testing.T) {
	base := os.Getenv("MISTUI_E2E_BASE")
	if base == "" {
		t.Skip("MISTUI_E2E_BASE not set")
	}
	origin := os.Getenv("MISTUI_E2E_ORIGIN")
	if origin == "" {
		origin = base
	}

	// Bootstrap trust from the device's own CA, like a first-boot user.
	transport := http.DefaultTransport
	if strings.HasPrefix(base, "https://") {
		insecure := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
		res, err := insecure.Get(base + "/ca.pem")
		if err != nil {
			t.Fatalf("fetch /ca.pem: %v", err)
		}
		pemBytes, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			t.Fatal("bad CA PEM from /ca.pem")
		}
		transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}

	jar, _ := cookiejar.New(nil)
	owner := &http.Client{Jar: jar, Transport: transport}

	// Refuse to touch a provisioned device — this test claims ownership.
	res, err := owner.Get(base + "/api/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	var health struct {
		OK          bool `json:"ok"`
		Provisioned bool `json:"provisioned"`
	}
	if err := jsonDecode(res, &health); err != nil || !health.OK {
		t.Fatalf("health: %v %+v", err, health)
	}
	if health.Provisioned {
		t.Fatal("target is already provisioned; point MISTUI_E2E_BASE at a scratch instance")
	}

	f := newFakeAuthenticator(t)
	f.origin = origin

	// Provision + login-from-scratch, real ceremonies over the wire.
	finish := register(t, owner, base, f)
	if rc, _ := finish["recoveryCode"].(string); rc == "" {
		t.Fatal("no recovery code from live provisioning")
	}
	jar2, _ := cookiejar.New(nil)
	fresh := &http.Client{Jar: jar2, Transport: transport}
	loginPasskey(t, fresh, base, f)

	// Import a dummy-but-valid config; safe AllowedIPs (see file comment).
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.99.88.2/32
DNS = 10.99.88.1

[Peer]
PublicKey = %s
AllowedIPs = 10.99.88.0/24
Endpoint = 192.0.2.1:51820
PersistentKeepalive = 25
`, e2eKey(t), e2eKey(t))

	code, body := post(t, fresh, base+"/api/vpn/import", map[string]string{"config": conf})
	if code != http.StatusOK {
		t.Fatalf("vpn/import: %d %v", code, body)
	}

	code, cfg := post(t, fresh, base+"/api/vpn/up", nil)
	if code != http.StatusOK {
		t.Fatalf("vpn/up: %d %v", code, cfg)
	}

	// ifup is asynchronous — netifd takes a couple of seconds to create
	// the device. Poll, like the UI does.
	var status struct {
		Up     bool   `json:"up"`
		Detail string `json:"detail"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		res, err = fresh.Get(base + "/api/vpn/status")
		if err != nil {
			t.Fatal(err)
		}
		if err := jsonDecode(res, &status); err != nil {
			t.Fatal(err)
		}
		if status.Up || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if !status.Up || !strings.Contains(status.Detail, "wg0") {
		t.Fatalf("tunnel not visible after up: %+v", status)
	}

	if code, body := post(t, fresh, base+"/api/vpn/down", nil); code != http.StatusOK {
		t.Fatalf("vpn/down: %d %v", code, body)
	}
	t.Logf("live E2E OK against %s", base)
}

func jsonDecode(res *http.Response, v any) error {
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(v)
}
