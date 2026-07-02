// Package netcfg handles small network-privacy tasks — currently MAC
// address randomization. It shells out to iproute2; netifd/UCI remains the
// owner of interface topology (MistUI never touches DSA or the switch).
package netcfg

import (
	"context"
	"crypto/rand"
	"fmt"
	"os/exec"
)

// RandomMAC returns a locally-administered, unicast MAC address.
func RandomMAC() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[0] = (b[0] | 0x02) &^ 0x01 // set locally-administered, clear multicast
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5]), nil
}

// RollMAC assigns a fresh randomized MAC to iface and returns it. Callers
// (or netifd) are responsible for any down/up cycle the driver requires.
func RollMAC(ctx context.Context, iface string) (string, error) {
	mac, err := RandomMAC()
	if err != nil {
		return "", err
	}
	if err := exec.CommandContext(ctx, "ip", "link", "set", "dev", iface, "address", mac).Run(); err != nil {
		return "", err
	}
	return mac, nil
}
