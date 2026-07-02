package netcfg

//go:generate go run ./gen/gen_ouis.go

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// decodeOUIs unpacks a generated hex constant into 3-byte prefixes. It
// panics on malformed input — the data is generated and compiled in, so a
// failure is a build-time bug, never a runtime condition.
func decodeOUIs(h string) [][3]byte {
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw)%3 != 0 {
		panic("netcfg: corrupt generated OUI data")
	}
	out := make([][3]byte, len(raw)/3)
	for i := range out {
		copy(out[i][:], raw[i*3:i*3+3])
	}
	return out
}

// Identity is the fingerprint the upstream (hotel) network sees: the STA
// MAC and the DHCP hostname, generated together so a spoofed vendor OUI is
// never paired with a mismatched name — the pairing is the whole point.
type Identity struct {
	MAC      string `json:"mac"`
	Hostname string `json:"hostname,omitempty"`
	Profile  string `json:"profile"`
}

// Profile is a device-identity template. A profile with real vendor OUIs
// mimics that device (globally-administered MAC + matching hostname); the
// zero-OUI "generic" profile emits a locally-administered random MAC and no
// hostname — the honest "I am some random device" identity.
//
// OUIs are a curated, representative sample per vendor, not the full IEEE
// registration; the network's lookup only reads the 3-byte prefix, so a
// handful per vendor suffices. Extend the pools freely — realism scales
// with variety, and every entry here is a real assignment (LA bit clear).
type profile struct {
	key   string
	label string
	ouis  [][3]byte
	names []string
}

// OUI pools come from the IEEE registry (oui_data.go, regenerate with
// `go generate`). Hostnames are a spread of plausible real models so a
// rolled identity doesn't repeat a single tell-tale name.
var profiles = []profile{
	{key: "generic", label: "Generic randomized"},
	{
		key: "apple", label: "Apple iPhone",
		ouis: decodeOUIs(appleOUIHex),
		// iOS sends the user-set device name; "iPhone" is the default and
		// overwhelmingly the most common, with a few named variants.
		names: []string{"iPhone", "iPhone", "iPhone", "iPhones-iPhone", "Johns-iPhone", "iPhone-15", "iPhone-14"},
	},
	{
		key: "samsung", label: "Samsung Galaxy",
		ouis: decodeOUIs(samsungOUIHex),
		names: []string{
			"Galaxy-S24", "Galaxy-S24-Ultra", "Galaxy-S23", "Galaxy-S23-FE",
			"Galaxy-S22", "Galaxy-A54", "Galaxy-A34", "Galaxy-Z-Flip5", "Galaxy-Note20",
		},
	},
	{
		key: "pixel", label: "Google Pixel",
		ouis: decodeOUIs(googleOUIHex),
		names: []string{
			"Pixel-8", "Pixel-8-Pro", "Pixel-8a", "Pixel-7", "Pixel-7-Pro",
			"Pixel-7a", "Pixel-6", "Pixel-6a", "Pixel-Fold",
		},
	},
}

// ProfileInfo is the API-facing view of a profile (no OUI internals).
type ProfileInfo struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Profiles lists the available identity profiles in display order.
func Profiles() []ProfileInfo {
	out := make([]ProfileInfo, len(profiles))
	for i, p := range profiles {
		out[i] = ProfileInfo{Key: p.key, Label: p.label}
	}
	return out
}

// ValidProfile reports whether key names a known profile.
func ValidProfile(key string) bool {
	for _, p := range profiles {
		if p.key == key {
			return true
		}
	}
	return false
}

func profileByKey(key string) profile {
	for _, p := range profiles {
		if p.key == key {
			return p
		}
	}
	return profiles[0] // generic
}

// GenerateIdentity builds a fresh MAC + hostname for the named profile.
// Generic → locally-administered random MAC, no hostname. Vendor → a real
// OUI from the pool with random trailing bytes, plus a matching hostname.
func GenerateIdentity(key string) (Identity, error) {
	p := profileByKey(key)
	// Two selector bytes + six MAC bytes.
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return Identity{}, err
	}
	sel1, sel2 := int(raw[0]), int(raw[1])
	b := raw[2:8]

	var host string
	if len(p.ouis) == 0 {
		b[0] = (b[0] | 0x02) &^ 0x01 // locally-administered, unicast
	} else {
		oui := p.ouis[sel1%len(p.ouis)]
		b[0], b[1], b[2] = oui[0], oui[1], oui[2]
		if len(p.names) > 0 {
			host = p.names[sel2%len(p.names)]
		}
	}
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	return Identity{MAC: mac, Hostname: host, Profile: p.key}, nil
}

// RandomMAC returns a locally-administered, unicast MAC — the generic
// identity's address, kept as a standalone helper for callers that only
// need a throwaway MAC.
func RandomMAC() (string, error) {
	id, err := GenerateIdentity("generic")
	return id.MAC, err
}
