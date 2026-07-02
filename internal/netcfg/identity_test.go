package netcfg

import (
	"encoding/hex"
	"fmt"
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

// poolPrefixes returns the "xx:xx:xx" prefixes for a profile's OUI pool.
func poolPrefixes(key string) map[string]bool {
	m := map[string]bool{}
	for _, o := range profileByKey(key).ouis {
		m[fmt.Sprintf("%02x:%02x:%02x", o[0], o[1], o[2])] = true
	}
	return m
}

func TestVendorIdentityUsesRealOUIAndHostname(t *testing.T) {
	hostPrefix := map[string]string{"apple": "iPhone", "samsung": "Galaxy", "pixel": "Pixel"}
	for _, profile := range []string{"apple", "samsung", "pixel"} {
		pool := poolPrefixes(profile)
		if len(pool) < 50 {
			t.Fatalf("%s pool is only %d OUIs — expected deep pools from the IEEE registry", profile, len(pool))
		}
		sawOUIs := map[string]bool{}
		sawNames := map[string]bool{}
		for i := 0; i < 200; i++ {
			id, err := GenerateIdentity(profile)
			if err != nil {
				t.Fatal(err)
			}
			if o := firstOctet(t, id.MAC); o&0x02 != 0 {
				t.Errorf("%s MAC %s has the locally-administered bit set", profile, id.MAC)
			}
			prefix := id.MAC[0:8]
			if !pool[prefix] {
				t.Errorf("%s MAC %s uses an OUI outside the pool", profile, id.MAC)
			}
			sawOUIs[prefix] = true
			sawNames[id.Hostname] = true
			if !strings.Contains(id.Hostname, hostPrefix[profile]) {
				t.Errorf("%s hostname %q missing %q", profile, id.Hostname, hostPrefix[profile])
			}
		}
		// Deep pool → many distinct OUIs and hostnames across 200 draws.
		if len(sawOUIs) < 20 {
			t.Errorf("%s varied its OUI only %d times in 200 draws", profile, len(sawOUIs))
		}
		if len(sawNames) < 2 {
			t.Errorf("%s never varied its hostname", profile)
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
