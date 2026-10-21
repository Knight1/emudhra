package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testScalar is the private scalar of the synthetic test CA. It must not be one
// of the real eMudhra scalars (4, 56, 66, 115, 155, 156, 230, 237): Go 1.26.10
// and 1.27.3 distrust those public keys, so chain verification would fail.
const testScalar = 3

// testRSAKey is generated once because RSA key generation is slow.
var testRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// scalarKey returns the P-384 private key with scalar d.
func scalarKey(t *testing.T, d byte) *ecdsa.PrivateKey {
	t.Helper()
	raw := make([]byte, 48)
	raw[47] = d
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func caTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func writePEM(t *testing.T, path, typ string, der []byte) string {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeCA writes a self-signed P-384 CA whose private scalar is d to
// dir/ca.pem. mod, if set, adjusts the template before signing.
func writeCA(t *testing.T, dir string, d byte, mod func(*x509.Certificate)) string {
	t.Helper()
	key := scalarKey(t, d)
	tmpl := caTemplate("Weak Test CA")
	if mod != nil {
		mod(tmpl)
	}
	c := newTestCert(t, tmpl, tmpl, &key.PublicKey, key)
	return writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", c.Raw)
}

// writeWeakCA writes a self-signed P-384 CA whose private scalar is d.
func writeWeakCA(t *testing.T, dir string, d byte) string {
	return writeCA(t, dir, d, nil)
}

// writeRSACA writes a self-signed RSA CA to dir/rsa-ca.pem.
func writeRSACA(t *testing.T, dir string) string {
	t.Helper()
	key := testRSAKey()
	tmpl := caTemplate("RSA Test CA")
	c := newTestCert(t, tmpl, tmpl, &key.PublicKey, key)
	return writePEM(t, filepath.Join(dir, "rsa-ca.pem"), "CERTIFICATE", c.Raw)
}

// writeRootedCA writes a root (dir/root.pem) and a weak P-384 CA with scalar
// testScalar signed by it (dir/ca.pem) and returns both paths.
func writeRootedCA(t *testing.T, dir string) (caPath, rootPath string) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := caTemplate("Test Root")
	root := newTestCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	caKey := scalarKey(t, testScalar)
	ca := newTestCert(t, caTemplate("Weak Test CA"), root, &caKey.PublicKey, rootKey)
	return writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", ca.Raw),
		writePEM(t, filepath.Join(dir, "root.pem"), "CERTIFICATE", root.Raw)
}

// writeECKey writes key as an "EC PRIVATE KEY" PEM file.
func writeECKey(t *testing.T, path string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, path, "EC PRIVATE KEY", der)
}

// writePKCS8Key writes key as a "PRIVATE KEY" PEM file.
func writePKCS8Key(t *testing.T, path string, key crypto.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writePEM(t, path, "PRIVATE KEY", der)
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
