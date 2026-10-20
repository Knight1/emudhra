package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	if err := run(cfg, runOptions{}, &out); err != nil {
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
	if err := run(cfg, runOptions{show: true}, &out); err != nil {
		t.Fatal(err)
	}
	certs := parsePEMCerts(t, out.Bytes())
	if len(certs) != 1 || certs[0].IsCA {
		t.Fatalf("-show should print exactly the leaf certificate, got %d certs:\n%s", len(certs), out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Errorf("-show wrote output files")
	}
}

func TestRecoveryBound(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 200))
	cfg.MaxScalar = 100
	if err := run(cfg, runOptions{show: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no private scalar") {
		t.Fatalf("expected recovery failure, got %v", err)
	}
}

func TestValidityCap(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 4))
	cfg.Leaf.ValidityHours = 24 * 30
	if err := run(cfg, runOptions{show: true}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected validity cap error")
	}
}

func TestShowChain(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 4))

	var out bytes.Buffer
	if err := run(cfg, runOptions{show: true, chain: true}, &out); err != nil {
		t.Fatal(err)
	}
	certs := parsePEMCerts(t, out.Bytes())
	if len(certs) != 2 || certs[0].IsCA || !certs[1].IsCA {
		t.Fatalf("expected leaf + CA, got %d certs", len(certs))
	}
	if err := certs[0].CheckSignatureFrom(certs[1]); err != nil {
		t.Errorf("chain order: %v", err)
	}
}

func TestApplySANs(t *testing.T) {
	lc := LeafConfig{DNSNames: []string{"from-config.example"}}
	err := applySANs(&lc, []string{"a.example", "DNS:b.example", "192.0.2.7", "2001:db8::1", "IP:::1",
		"ops@a.example", "https://a.example/x", "URI:spiffe://a/b"})
	if err != nil {
		t.Fatal(err)
	}
	want := LeafConfig{
		DNSNames:       []string{"a.example", "b.example"},
		IPAddresses:    []string{"192.0.2.7", "2001:db8::1", "::1"},
		EmailAddresses: []string{"ops@a.example"},
		URIs:           []string{"https://a.example/x", "spiffe://a/b"},
	}
	if fmt.Sprint(lc) != fmt.Sprint(want) {
		t.Errorf("got  %+v\nwant %+v", lc, want)
	}
	if err := applySANs(&lc, []string{"bogus:x"}); err == nil {
		t.Error("expected error for unknown SAN type")
	}
}

func TestSANFlagSplitsCommas(t *testing.T) {
	var s sanFlag
	s.Set("a.example, IP:192.0.2.1")
	s.Set("b.example")
	if got := s.String(); got != "a.example,IP:192.0.2.1,b.example" {
		t.Errorf("got %q", got)
	}
}

func TestCLISANsInLeaf(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 4))
	if err := applySANs(&cfg.Leaf, []string{"cli.example", "198.51.100.1", "URI:https://cli.example/"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(cfg, runOptions{show: true}, &out); err != nil {
		t.Fatal(err)
	}
	leaf := parsePEMCerts(t, out.Bytes())[0]
	got := strings.Join(subjectAltNames(leaf), ",")
	if got != "DNS:cli.example,IP:198.51.100.1,URI:https://cli.example/" || leaf.Subject.CommonName != "cli.example" {
		t.Errorf("SANs %q, CN %q", got, leaf.Subject.CommonName)
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

func TestJSONAddChain(t *testing.T) {
	for _, show := range []bool{true, false} {
		dir := t.TempDir()
		cfg := testConfig(dir, writeWeakCA(t, dir, 4))

		var out, diag bytes.Buffer
		if err := run(cfg, runOptions{show: show, json: true, diag: &diag}, &out); err != nil {
			t.Fatalf("show=%t: %v", show, err)
		}
		var req addChainRequest
		dec := json.NewDecoder(&out)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			t.Fatalf("show=%t: stdout is not add-chain JSON: %v", show, err)
		}
		if dec.More() {
			t.Errorf("show=%t: extra data after JSON", show)
		}
		if len(req.Chain) != 2 {
			t.Fatalf("show=%t: expected leaf + CA, got %d entries", show, len(req.Chain))
		}
		leaf, err := x509.ParseCertificate(req.Chain[0])
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(req.Chain[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := leaf.CheckSignatureFrom(ca); err != nil {
			t.Errorf("show=%t: chain order: %v", show, err)
		}
		if gotChecks := strings.Contains(diag.String(), "[ OK ] chain verification"); gotChecks == show {
			t.Errorf("show=%t: checks on diag = %t", show, gotChecks)
		}
	}
}
