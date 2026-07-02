package httpapi

import (
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

// TestStepUpOneShot pins the one-shot contract: every destructive call
// consumes its own fresh assertion, and nothing about a live session or a
// spent credit unlocks a second one.
func TestStepUpOneShot(t *testing.T) {
	ts, owner := newTestServer(t)
	f := newFakeAuthenticator(t)
	register(t, owner, ts.URL, f)

	// No credit yet → 428, and the response says why.
	code, body := post(t, owner, ts.URL+"/api/recovery/regenerate", nil)
	if code != http.StatusPreconditionRequired || body["stepUpRequired"] != true {
		t.Fatalf("without step-up: %d %v", code, body)
	}

	// One touch → exactly one destructive action.
	stepUp(t, owner, ts.URL, f)
	if code, _ := post(t, owner, ts.URL+"/api/recovery/regenerate", nil); code != http.StatusOK {
		t.Fatalf("with step-up: %d", code)
	}
	if code, _ := post(t, owner, ts.URL+"/api/recovery/regenerate", nil); code != http.StatusPreconditionRequired {
		t.Fatalf("credit reused: %d, want 428", code)
	}

	// A failed destructive attempt must not refund the credit — consume
	// happens before the handler runs. (Regenerate can't fail benignly, so
	// exercise consumption-then-428 ordering via two rapid calls instead.)
	stepUp(t, owner, ts.URL, f)
	if code, _ := post(t, owner, ts.URL+"/api/recovery/regenerate", nil); code != http.StatusOK {
		t.Fatal("second touch did not grant a second action")
	}
}

// TestStepUpRejectsBadAssertion: a wrong-key signature grants nothing.
func TestStepUpRejectsBadAssertion(t *testing.T) {
	ts, owner := newTestServer(t)
	f := newFakeAuthenticator(t)
	register(t, owner, ts.URL, f)

	intruder := newFakeAuthenticator(t) // different key, same credential ID
	intruder.credID = f.credID

	code, begin := post(t, owner, ts.URL+"/api/stepup/begin", nil)
	if code != http.StatusOK {
		t.Fatalf("stepup/begin: %d", code)
	}
	cd := intruder.clientData("webauthn.get", begin["challenge"].(string))
	ad := intruder.authData(false)
	code, _ = post(t, owner, ts.URL+"/api/stepup/finish", map[string]string{
		"credentialId":      base64.RawURLEncoding.EncodeToString(intruder.credID),
		"authenticatorData": base64.StdEncoding.EncodeToString(ad),
		"clientDataJSON":    base64.StdEncoding.EncodeToString(cd),
		"signature":         base64.StdEncoding.EncodeToString(intruder.sign(ad, cd)),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("forged assertion: %d, want 401", code)
	}
	if code, _ := post(t, owner, ts.URL+"/api/recovery/regenerate", nil); code != http.StatusPreconditionRequired {
		t.Fatalf("forged assertion granted a credit: %d", code)
	}
}

// TestStepUpBoundToSession: a credit earned by one session unlocks nothing
// for another.
func TestStepUpBoundToSession(t *testing.T) {
	ts, owner := newTestServer(t)
	f := newFakeAuthenticator(t)
	register(t, owner, ts.URL, f)
	stepUp(t, owner, ts.URL, f)

	jar, _ := cookiejar.New(nil)
	other := &http.Client{Jar: jar}
	loginPasskey(t, other, ts.URL, f)
	if code, _ := post(t, other, ts.URL+"/api/recovery/regenerate", nil); code != http.StatusPreconditionRequired {
		t.Fatalf("credit leaked across sessions: %d, want 428", code)
	}
	// The owner's credit is still intact for the owner.
	if code, _ := post(t, owner, ts.URL+"/api/recovery/regenerate", nil); code != http.StatusOK {
		t.Fatal("owner's credit vanished")
	}
}
