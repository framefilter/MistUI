// Package auth implements MistUI's minimal WebAuthn: just enough to verify
// a login assertion against a stored credential, with no attestation path.
//
// WebAuthn registration here is trust-on-first-use — we record the
// authenticator's COSE public key without verifying its attestation
// statement. That deliberately omits the heavy half of a full WebAuthn
// library (TPM/packed/android-key attestation, the metadata service); the
// remaining login-assertion verify is a few stdlib crypto calls, which is
// what lets the whole daemon stay small enough for a 16 MB-flash router.
package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// coseECKey is the subset of a COSE_Key (RFC 8152) we need for an EC2
// P-256 public key: kty/alg plus the curve and affine coordinates.
type coseECKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// ErrUnsupportedKey is returned for any COSE key that is not EC2/P-256/ES256.
var ErrUnsupportedKey = errors.New("auth: unsupported COSE key (want EC2 P-256 ES256)")

// ParseCOSE decodes a stored COSE EC2 public key into an ecdsa.PublicKey.
func ParseCOSE(b []byte) (*ecdsa.PublicKey, error) {
	var k coseECKey
	if err := cbor.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	// kty 2 = EC2, crv 1 = P-256, alg -7 = ES256.
	if k.Kty != 2 || k.Crv != 1 || k.Alg != -7 {
		return nil, ErrUnsupportedKey
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(k.X),
		Y:     new(big.Int).SetBytes(k.Y),
	}, nil
}

// VerifyAssertion checks a WebAuthn login signature, which is computed over
// authenticatorData ‖ SHA-256(clientDataJSON). The signature is ASN.1 DER
// as produced by navigator.credentials.get for an ES256 credential.
//
// This is the entire cryptographic cost of a MistUI login.
func VerifyAssertion(pub *ecdsa.PublicKey, authData, clientDataJSON, sig []byte) bool {
	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

// NewToken returns a URL-safe, 128-bit random token for sessions and
// recovery codes.
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
