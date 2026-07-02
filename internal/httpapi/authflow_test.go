package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/framefilter/mistui/internal/store"
	"github.com/framefilter/mistui/internal/vpn"
	"github.com/fxamacker/cbor/v2"
)

const (
	testRP     = "mist.lan"
	testOrigin = "https://mist.lan"
)

// fakeAuthenticator plays the browser+passkey side of both ceremonies.
type fakeAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	rp     string
	origin string
}

func newFakeAuthenticator(t *testing.T) *fakeAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAuthenticator{key: key, credID: []byte("fake-cred-1"), rp: testRP, origin: testOrigin}
}

func (f *fakeAuthenticator) clientData(ceremony, challenge string) []byte {
	b, _ := json.Marshal(map[string]string{
		"type": ceremony, "challenge": challenge, "origin": f.origin,
	})
	return b
}

func (f *fakeAuthenticator) authData(withCred bool) []byte {
	h := sha256.Sum256([]byte(f.rp))
	ad := append([]byte{}, h[:]...)
	flags := byte(0x01) // UP
	if withCred {
		flags |= 0x40 // AT
	}
	ad = append(ad, flags, 0, 0, 0, 1)
	if withCred {
		cose, _ := cbor.Marshal(map[int]any{
			1: 2, 3: -7, -1: 1,
			-2: f.key.PublicKey.X.Bytes(), -3: f.key.PublicKey.Y.Bytes(),
		})
		ad = append(ad, make([]byte, 16)...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(f.credID)))
		ad = append(ad, l[:]...)
		ad = append(ad, f.credID...)
		ad = append(ad, cose...)
	}
	return ad
}

func (f *fakeAuthenticator) attestationObject() []byte {
	b, _ := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": f.authData(true),
	})
	return b
}

func (f *fakeAuthenticator) sign(authData, clientDataJSON []byte) []byte {
	ch := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), ch[:]...)
	digest := sha256.Sum256(signed)
	sig, _ := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	return sig
}

// --- harness ---

func newTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st, vpn.NewUCIConnector(), testRP, []string{testOrigin})
	ts := httptest.NewServer(srv.api)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar}
}

func post(t *testing.T, c *http.Client, url string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	res, err := c.Post(url, "application/json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func register(t *testing.T, c *http.Client, base string, f *fakeAuthenticator) map[string]any {
	t.Helper()
	code, begin := post(t, c, base+"/api/register/begin", nil)
	if code != http.StatusOK {
		t.Fatalf("register/begin: %d", code)
	}
	cd := f.clientData("webauthn.create", begin["challenge"].(string))
	code, finish := post(t, c, base+"/api/register/finish", map[string]string{
		"clientDataJSON":    base64.StdEncoding.EncodeToString(cd),
		"attestationObject": base64.StdEncoding.EncodeToString(f.attestationObject()),
	})
	if code != http.StatusOK {
		t.Fatalf("register/finish: %d %v", code, finish)
	}
	return finish
}

// loginPasskey runs the full login ceremony, failing the test on any error.
func loginPasskey(t *testing.T, c *http.Client, base string, f *fakeAuthenticator) {
	t.Helper()
	code, begin := post(t, c, base+"/api/login/begin", nil)
	if code != http.StatusOK {
		t.Fatalf("login/begin: %d", code)
	}
	cd := f.clientData("webauthn.get", begin["challenge"].(string))
	ad := f.authData(false)
	code, body := post(t, c, base+"/api/login/finish", map[string]string{
		"credentialId":      base64.RawURLEncoding.EncodeToString(f.credID),
		"authenticatorData": base64.StdEncoding.EncodeToString(ad),
		"clientDataJSON":    base64.StdEncoding.EncodeToString(cd),
		"signature":         base64.StdEncoding.EncodeToString(f.sign(ad, cd)),
	})
	if code != http.StatusOK {
		t.Fatalf("login/finish: %d %v", code, body)
	}
}

// --- tests ---

func TestProvisionLoginRecoveryFlow(t *testing.T) {
	ts, owner := newTestServer(t)
	f := newFakeAuthenticator(t)

	// TOFU provisioning issues the one-time recovery code and a session.
	finish := register(t, owner, ts.URL, f)
	recovery, _ := finish["recoveryCode"].(string)
	if recovery == "" {
		t.Fatal("first registration returned no recovery code")
	}
	if code, _ := post(t, owner, ts.URL+"/api/vpn/down", nil); code == http.StatusUnauthorized {
		t.Fatal("session cookie from registration not accepted")
	}

	// A second, anonymous registration attempt must be refused.
	anon := &http.Client{}
	if code, _ := post(t, anon, ts.URL+"/api/register/begin", nil); code != http.StatusForbidden {
		t.Fatalf("anonymous register/begin after provisioning: %d, want 403", code)
	}

	// Passkey login from a fresh client.
	jar, _ := cookiejar.New(nil)
	fresh := &http.Client{Jar: jar}
	code, begin := post(t, fresh, ts.URL+"/api/login/begin", nil)
	if code != http.StatusOK {
		t.Fatalf("login/begin: %d", code)
	}
	cd := f.clientData("webauthn.get", begin["challenge"].(string))
	ad := f.authData(false)
	code, _ = post(t, fresh, ts.URL+"/api/login/finish", map[string]string{
		"credentialId":      base64.RawURLEncoding.EncodeToString(f.credID),
		"authenticatorData": base64.StdEncoding.EncodeToString(ad),
		"clientDataJSON":    base64.StdEncoding.EncodeToString(cd),
		"signature":         base64.StdEncoding.EncodeToString(f.sign(ad, cd)),
	})
	if code != http.StatusOK {
		t.Fatalf("login/finish: %d", code)
	}

	// A replay of the same ceremony must die on the consumed challenge.
	code, _ = post(t, fresh, ts.URL+"/api/login/finish", map[string]string{
		"credentialId":      base64.RawURLEncoding.EncodeToString(f.credID),
		"authenticatorData": base64.StdEncoding.EncodeToString(ad),
		"clientDataJSON":    base64.StdEncoding.EncodeToString(cd),
		"signature":         base64.StdEncoding.EncodeToString(f.sign(ad, cd)),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("replayed login accepted: %d", code)
	}

	// Recovery code works exactly once.
	jar2, _ := cookiejar.New(nil)
	rec := &http.Client{Jar: jar2}
	if code, _ := post(t, rec, ts.URL+"/api/login/recovery", map[string]string{"code": recovery}); code != http.StatusOK {
		t.Fatalf("recovery login: %d", code)
	}
	if code, _ := post(t, rec, ts.URL+"/api/login/recovery", map[string]string{"code": recovery}); code != http.StatusUnauthorized {
		t.Fatalf("recovery code worked twice: %d", code)
	}

	// An authenticated session can mint a fresh code…
	code, regen := post(t, rec, ts.URL+"/api/recovery/regenerate", nil)
	newCode, _ := regen["recoveryCode"].(string)
	if code != http.StatusOK || newCode == "" {
		t.Fatalf("regenerate: %d %v", code, regen)
	}
	// …and the new one works for a different anonymous client.
	jar3, _ := cookiejar.New(nil)
	rec2 := &http.Client{Jar: jar3}
	if code, _ := post(t, rec2, ts.URL+"/api/login/recovery", map[string]string{"code": newCode}); code != http.StatusOK {
		t.Fatalf("regenerated recovery login: %d", code)
	}
}

func TestLoginRejectsWrongOriginAndUnprovisioned(t *testing.T) {
	ts, c := newTestServer(t)

	// login/begin before provisioning → 409.
	if code, _ := post(t, c, ts.URL+"/api/login/begin", nil); code != http.StatusConflict {
		t.Fatalf("unprovisioned login/begin: %d, want 409", code)
	}

	f := newFakeAuthenticator(t)
	register(t, c, ts.URL, f)

	// Ceremony from a hostile origin must fail even with a valid signature.
	jar, _ := cookiejar.New(nil)
	fresh := &http.Client{Jar: jar}
	code, begin := post(t, fresh, ts.URL+"/api/login/begin", nil)
	if code != http.StatusOK {
		t.Fatalf("login/begin: %d", code)
	}
	cd, _ := json.Marshal(map[string]string{
		"type": "webauthn.get", "challenge": begin["challenge"].(string),
		"origin": "https://evil.example",
	})
	ad := f.authData(false)
	code, _ = post(t, fresh, ts.URL+"/api/login/finish", map[string]string{
		"credentialId":      base64.RawURLEncoding.EncodeToString(f.credID),
		"authenticatorData": base64.StdEncoding.EncodeToString(ad),
		"clientDataJSON":    base64.StdEncoding.EncodeToString(cd),
		"signature":         base64.StdEncoding.EncodeToString(f.sign(ad, cd)),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong-origin login: %d, want 401", code)
	}
}
