package netcfg

import (
	"crypto/rand"
	"fmt"
)

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

var profiles = []profile{
	{key: "generic", label: "Generic randomized"},
	{
		key: "apple", label: "Apple iPhone",
		ouis:  [][3]byte{{0x3c, 0x15, 0xc2}, {0x40, 0x6c, 0x8f}, {0xf0, 0x18, 0x98}, {0xa4, 0x83, 0xe7}, {0xac, 0xbc, 0x32}},
		names: []string{"iPhone"},
	},
	{
		key: "samsung", label: "Samsung Galaxy",
		ouis:  [][3]byte{{0x5c, 0x0a, 0x5b}, {0x88, 0x32, 0x9b}, {0xe8, 0x50, 0x8b}, {0x34, 0x23, 0xba}},
		names: []string{"Galaxy-S24", "Galaxy-S23", "Galaxy-S22", "Galaxy-A54"},
	},
	{
		key: "pixel", label: "Google Pixel",
		ouis:  [][3]byte{{0x3c, 0x5a, 0xb4}, {0xf4, 0xf5, 0xd8}, {0xf8, 0x8f, 0xca}, {0x00, 0x1a, 0x11}},
		names: []string{"Pixel-8", "Pixel-8-Pro", "Pixel-7", "Pixel-6a"},
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
