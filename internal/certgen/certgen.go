// Package certgen maintains the device's TLS material. A travel router has
// no public identity a CA could vouch for — and browsers refuse WebAuthn on
// sites with certificate errors, so "click through the warning" is not an
// option. The honest end state is a one-time trust install: the device
// mints its own CA, name-constrained to the UI hostname so trusting it
// grants nothing beyond this device, and serves the CA cert for the user to
// install. The TLS leaf is signed by that CA and renewed automatically.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Leaf lifetime stays under Apple's 825-day ceiling for TLS certs; renewal
// happens at boot once less than renewBefore remains. A router that stays
// up past the leaf's expiry heals on its next reboot.
const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 800 * 24 * time.Hour
	renewBefore  = 90 * 24 * time.Hour
)

// Material points at the PEM files EnsureMaterial maintains.
type Material struct {
	CertPath string // TLS leaf certificate
	KeyPath  string // TLS leaf private key
	CAPath   string // device CA certificate — the one users trust once
}

// EnsureMaterial returns TLS material for host under dir, creating the
// device CA on first boot and (re)issuing the leaf when missing or near
// expiry. Factory reset just deletes dir.
func EnsureMaterial(dir, host string) (Material, error) {
	m := Material{
		CertPath: filepath.Join(dir, "cert.pem"),
		KeyPath:  filepath.Join(dir, "key.pem"),
		CAPath:   filepath.Join(dir, "ca.pem"),
	}
	caKeyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Material{}, err
	}

	caCert, caKey, err := loadCA(m.CAPath, caKeyPath)
	if err != nil {
		// Unusable or absent CA: mint a fresh one; the old leaf dies with it.
		caCert, caKey, err = createCA(m.CAPath, caKeyPath, host)
		if err != nil {
			return Material{}, err
		}
		_ = os.Remove(m.CertPath)
		_ = os.Remove(m.KeyPath)
	}

	if !leafUsable(m.CertPath, m.KeyPath, host) {
		if err := createLeaf(m.CertPath, m.KeyPath, host, caCert, caKey); err != nil {
			return Material{}, err
		}
	}
	return m, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, err := readCert(certPath)
	if err != nil {
		return nil, nil, err
	}
	der, err := readPEM(keyPath, "EC PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA || time.Now().After(cert.NotAfter.Add(-renewBefore)) {
		return nil, nil, errors.New("certgen: CA unusable or expiring")
	}
	return cert, key, nil
}

func createCA(certPath, keyPath, host string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "MistUI Device CA (" + host + ")"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		// The teeth: this CA can never vouch for anything but the UI
		// hostname, so installing it grants no MITM power elsewhere.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, nil, err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func leafUsable(certPath, keyPath, host string) bool {
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	cert, err := readCert(certPath)
	if err != nil {
		return false
	}
	return cert.VerifyHostname(host) == nil &&
		time.Now().Before(cert.NotAfter.Add(-renewBefore))
}

func createLeaf(certPath, keyPath, host string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)
}

// --- small PEM/file helpers ---

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func readPEM(path, typ string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != typ {
		return nil, errors.New("certgen: no " + typ + " block in " + path)
	}
	return block.Bytes, nil
}

func readCert(path string) (*x509.Certificate, error) {
	der, err := readPEM(path, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
