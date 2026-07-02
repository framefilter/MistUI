package netcfg

import (
	"encoding/hex"
	"strings"
	"testing"
)

func firstOctet(t *testing.T, mac string) byte {
	t.Helper()
	b, err := hex.DecodeString(mac[0:2])
	if err != nil {
		t.Fatalf("bad MAC %q: %v", mac, err)
	}
	return b[0]
}

func TestGenericIdentityIsLocallyAdministered(t *testing.T) {
	for i := 0; i < 50; i++ {
		id, err := GenerateIdentity("generic")
		if err != nil {
			t.Fatal(err)
		}
		o := firstOctet(t, id.MAC)
		if o&0x02 == 0 {
			t.Errorf("generic MAC %s missing locally-administered bit", id.MAC)
		}
		if o&0x01 != 0 {
			t.Errorf("generic MAC %s is multicast", id.MAC)
		}
		if id.Hostname != "" {
			t.Errorf("generic identity should send no hostname, got %q", id.Hostname)
		}
	}
}

func TestVendorIdentityUsesRealOUIAndHostname(t *testing.T) {
	cases := map[string]struct {
		ouiPrefixes []string
		hostPrefix  string
	}{
		"apple":   {[]string{"3c:15:c2", "40:6c:8f", "f0:18:98", "a4:83:e7", "ac:bc:32"}, "iPhone"},
		"samsung": {[]string{"5c:0a:5b", "88:32:9b", "e8:50:8b", "34:23:ba"}, "Galaxy-"},
		"pixel":   {[]string{"3c:5a:b4", "f4:f5:d8", "f8:8f:ca", "00:1a:11"}, "Pixel-"},
	}
	for profile, want := range cases {
		sawOUIs := map[string]bool{}
		for i := 0; i < 60; i++ {
			id, err := GenerateIdentity(profile)
			if err != nil {
				t.Fatal(err)
			}
			// A real vendor OUI is globally administered: LA bit clear.
			if o := firstOctet(t, id.MAC); o&0x02 != 0 {
				t.Errorf("%s MAC %s has the locally-administered bit set", profile, id.MAC)
			}
			prefix := id.MAC[0:8]
			var matched bool
			for _, p := range want.ouiPrefixes {
				if prefix == p {
					matched = true
				}
			}
			if !matched {
				t.Errorf("%s MAC %s uses an OUI outside the pool", profile, id.MAC)
			}
			sawOUIs[prefix] = true
			if !strings.HasPrefix(id.Hostname, want.hostPrefix) {
				t.Errorf("%s hostname %q lacks prefix %q", profile, id.Hostname, want.hostPrefix)
			}
		}
		if len(sawOUIs) < 2 && len(want.ouiPrefixes) > 1 {
			t.Errorf("%s never varied its OUI across 60 draws (%v)", profile, sawOUIs)
		}
	}
}

func TestUnknownProfileFallsBackToGeneric(t *testing.T) {
	id, err := GenerateIdentity("nonesuch")
	if err != nil {
		t.Fatal(err)
	}
	if id.Profile != "generic" || id.Hostname != "" {
		t.Errorf("unknown profile should fall back to generic, got %+v", id)
	}
}

func TestProfilesAndValidation(t *testing.T) {
	if !ValidProfile("apple") || ValidProfile("bogus") {
		t.Error("ValidProfile wrong")
	}
	got := Profiles()
	if len(got) != 4 || got[0].Key != "generic" {
		t.Fatalf("Profiles() = %+v", got)
	}
}
