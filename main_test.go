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
	"strings"
	"testing"
	"time"
)

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

func TestIssueAndCheck(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 4))

	var out bytes.Buffer
	if err := run(cfg, false, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	for _, want := range []string{"Recovered key:  d = 4", "[ OK ] chain verification", pocMarker} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "[FAIL]") {
		t.Errorf("unexpected failure:\n%s", out.String())
	}
	for _, p := range []string{cfg.Output.Cert, cfg.Output.Key, cfg.Output.Chain} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing output %s: %v", p, err)
		}
	}
}

func TestShowOnlyWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 4))

	var out bytes.Buffer
	if err := run(cfg, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "-----BEGIN CERTIFICATE-----") || strings.Contains(out.String(), "Checks") {
		t.Errorf("unexpected -show output:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Errorf("-show wrote output files")
	}
}

func TestRecoveryBound(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 200))
	cfg.MaxScalar = 100
	if err := run(cfg, true, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no private scalar") {
		t.Fatalf("expected recovery failure, got %v", err)
	}
}

func TestValidityCap(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 4))
	cfg.Leaf.ValidityHours = 24 * 30
	if err := run(cfg, true, &bytes.Buffer{}); err == nil {
		t.Fatal("expected validity cap error")
	}
}
