package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testScalar is the private scalar of the synthetic test CA. It must not be one
// of the real eMudhra scalars (4, 56, 66, 115, 155, 156, 230, 237): Go 1.26.10
// and 1.27.3 distrust those public keys, so chain verification would fail.
const testScalar = 3

// writeWeakCA writes a self-signed P-384 CA whose private scalar is d.
func writeWeakCA(t *testing.T, dir string, d byte) string {
	t.Helper()
	raw := make([]byte, 48)
	raw[47] = d
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), raw)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Weak Test CA", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testConfig(dir, caPath string) *Config {
	return &Config{
		CACert: caPath,
		Leaf: LeafConfig{
			DNSNames:    []string{"poc.example"},
			IPAddresses: []string{"192.0.2.1"},
		},
		Output: OutputConfig{
			Cert:  filepath.Join(dir, "out", "leaf.pem"),
			Key:   filepath.Join(dir, "out", "leaf.key"),
			Chain: filepath.Join(dir, "out", "chain.pem"),
		},
	}
}

func parsePEMCerts(t *testing.T, data []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("non-PEM output: %q", data)
	}
	return certs
}

func newTestCert(t *testing.T, tmpl, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
