package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// coseFromPub encodes a public key the way an authenticator would store it.
func coseFromPub(pub *ecdsa.PublicKey) ([]byte, error) {
	return cbor.Marshal(map[int]any{
		1:  2,             // kty: EC2
		3:  -7,            // alg: ES256
		-1: 1,             // crv: P-256
		-2: pub.X.Bytes(), // x
		-3: pub.Y.Bytes(), // y
	})
}

func TestParseCOSEAndVerifyAssertion(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	cose, err := coseFromPub(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode cose: %v", err)
	}
	pub, err := ParseCOSE(cose)
	if err != nil {
		t.Fatalf("ParseCOSE: %v", err)
	}

	// Reproduce what the browser signs: authData ‖ SHA256(clientDataJSON).
	authData := []byte("\x00\x01\x02 fake authenticator data")
	clientDataJSON := []byte(`{"type":"webauthn.get","challenge":"abc"}`)
	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !VerifyAssertion(pub, authData, clientDataJSON, sig) {
		t.Fatal("valid assertion rejected")
	}

	// A tampered clientDataJSON must fail.
	if VerifyAssertion(pub, authData, []byte(`{"type":"webauthn.get","challenge":"evil"}`), sig) {
		t.Fatal("tampered assertion accepted")
	}
}

func TestParseCOSERejectsNonP256(t *testing.T) {
	bad, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 2, -2: []byte{1}, -3: []byte{2}})
	if _, err := ParseCOSE(bad); err == nil {
		t.Fatal("expected error for non-P-256 curve")
	}
}

func TestNewTokenUnique(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if a == "" || a == b {
		t.Fatalf("tokens not unique/non-empty: %q %q", a, b)
	}
}
