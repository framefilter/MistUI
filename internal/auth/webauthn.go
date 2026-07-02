// WebAuthn ceremony verification: the checks both registration and login
// share (clientDataJSON, authenticator data) plus trust-on-first-use
// registration parsing. Attestation statements are deliberately ignored —
// see the package comment.
package auth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Ceremony types, per the WebAuthn spec's clientDataJSON.
const (
	CeremonyCreate = "webauthn.create"
	CeremonyGet    = "webauthn.get"
)

// authenticator-data flag bits.
const (
	flagUserPresent  = 1 << 0
	flagAttestedCred = 1 << 6
)

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// VerifyClientData parses clientDataJSON and checks the ceremony type, that
// the challenge is the one we issued (base64url, as the browser encodes it),
// and that the origin is one we serve.
func VerifyClientData(raw []byte, ceremony, wantChallenge string, origins []string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return fmt.Errorf("auth: bad clientDataJSON: %w", err)
	}
	if cd.Type != ceremony {
		return fmt.Errorf("auth: ceremony type %q, want %q", cd.Type, ceremony)
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(wantChallenge)) != 1 {
		return errors.New("auth: challenge mismatch")
	}
	for _, o := range origins {
		if cd.Origin == o {
			return nil
		}
	}
	return fmt.Errorf("auth: origin %q not allowed", cd.Origin)
}

// VerifyAuthData checks the fixed head of authenticator data: the RP ID hash
// binds the ceremony to our hostname, and the UP flag proves a human touched
// the authenticator.
func VerifyAuthData(authData []byte, rpID string) error {
	if len(authData) < 37 {
		return errors.New("auth: authenticator data too short")
	}
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(authData[:32], want[:]) != 1 {
		return errors.New("auth: rpIdHash mismatch")
	}
	if authData[32]&flagUserPresent == 0 {
		return errors.New("auth: user-present flag not set")
	}
	return nil
}

// attestationObject is the CBOR envelope from navigator.credentials.create.
// attStmt is intentionally absent: TOFU means we never look at it.
type attestationObject struct {
	Fmt      string `cbor:"fmt"`
	AuthData []byte `cbor:"authData"`
}

// ParseRegistration extracts the credential ID and COSE public key from a
// registration's attestationObject, verifying the RP binding and that the
// key is one we can later verify logins with (EC2/P-256/ES256).
//
// Layout of authData past the 37-byte head, when the AT flag is set:
// aaguid[16] ‖ credIdLen[2,BE] ‖ credId ‖ COSE key (CBOR).
func ParseRegistration(attObj []byte, rpID string) (credID []byte, cose []byte, err error) {
	var ao attestationObject
	if err := cbor.Unmarshal(attObj, &ao); err != nil {
		return nil, nil, fmt.Errorf("auth: bad attestationObject: %w", err)
	}
	ad := ao.AuthData
	if err := VerifyAuthData(ad, rpID); err != nil {
		return nil, nil, err
	}
	if ad[32]&flagAttestedCred == 0 {
		return nil, nil, errors.New("auth: no attested credential data")
	}
	rest := ad[37:]
	if len(rest) < 18 {
		return nil, nil, errors.New("auth: attested credential data truncated")
	}
	idLen := int(binary.BigEndian.Uint16(rest[16:18]))
	if len(rest) < 18+idLen {
		return nil, nil, errors.New("auth: credential ID truncated")
	}
	credID = append([]byte{}, rest[18:18+idLen]...)

	// The COSE key is the next CBOR item; extensions may follow it, so
	// decode exactly one item rather than requiring EOF.
	var raw cbor.RawMessage
	if err := cbor.NewDecoder(bytes.NewReader(rest[18+idLen:])).Decode(&raw); err != nil {
		return nil, nil, fmt.Errorf("auth: bad COSE key: %w", err)
	}
	if _, err := ParseCOSE(raw); err != nil {
		return nil, nil, err
	}
	return credID, []byte(raw), nil
}

// HashToken is how recovery codes are stored at rest: only the SHA-256 of
// the code ever touches flash.
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}
