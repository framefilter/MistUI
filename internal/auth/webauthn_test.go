package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// buildAuthData assembles authenticator data the way a real device would:
// rpIdHash ‖ flags ‖ signCount [‖ aaguid ‖ credIdLen ‖ credId ‖ COSE key].
func buildAuthData(rpID string, flags byte, credID, cose []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	ad := append([]byte{}, h[:]...)
	ad = append(ad, flags, 0, 0, 0, 1) // flags + signCount=1
	if flags&flagAttestedCred != 0 {
		ad = append(ad, make([]byte, 16)...) // zero aaguid
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
		ad = append(ad, l[:]...)
		ad = append(ad, credID...)
		ad = append(ad, cose...)
	}
	return ad
}

func TestParseRegistration(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose, err := coseFromPub(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte("test-credential-id")
	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": buildAuthData("mist.lan", flagUserPresent|flagAttestedCred, credID, cose),
	})
	if err != nil {
		t.Fatal(err)
	}

	gotID, gotCose, err := ParseRegistration(attObj, "mist.lan")
	if err != nil {
		t.Fatalf("ParseRegistration: %v", err)
	}
	if string(gotID) != string(credID) {
		t.Fatalf("credID = %q, want %q", gotID, credID)
	}
	if _, err := ParseCOSE(gotCose); err != nil {
		t.Fatalf("returned COSE unparseable: %v", err)
	}

	// Wrong RP: the rpIdHash check must reject it.
	if _, _, err := ParseRegistration(attObj, "evil.example"); err == nil {
		t.Fatal("registration for the wrong RP accepted")
	}
}

func TestParseRegistrationRequiresAttestedCred(t *testing.T) {
	attObj, _ := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": buildAuthData("mist.lan", flagUserPresent, nil, nil),
	})
	if _, _, err := ParseRegistration(attObj, "mist.lan"); err == nil {
		t.Fatal("authData without attested credential data accepted")
	}
}

func TestVerifyClientData(t *testing.T) {
	origins := []string{"https://mist.lan"}
	good := []byte(`{"type":"webauthn.get","challenge":"abc","origin":"https://mist.lan"}`)
	if err := VerifyClientData(good, CeremonyGet, "abc", origins); err != nil {
		t.Fatalf("valid clientData rejected: %v", err)
	}
	cases := map[string][]byte{
		"wrong type":      []byte(`{"type":"webauthn.create","challenge":"abc","origin":"https://mist.lan"}`),
		"wrong challenge": []byte(`{"type":"webauthn.get","challenge":"xyz","origin":"https://mist.lan"}`),
		"wrong origin":    []byte(`{"type":"webauthn.get","challenge":"abc","origin":"https://evil.example"}`),
	}
	for name, cd := range cases {
		if err := VerifyClientData(cd, CeremonyGet, "abc", origins); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyAuthDataFlags(t *testing.T) {
	// User-present flag missing → reject.
	ad := buildAuthData("mist.lan", 0, nil, nil)
	if err := VerifyAuthData(ad, "mist.lan"); err == nil {
		t.Fatal("authData without UP flag accepted")
	}
}
