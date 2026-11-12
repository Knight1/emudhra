package main

import (
	"bytes"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// crlConfig returns a config whose CA is a weak P-384 CA with scalar
// testScalar and whose CRL revokes two serials.
func crlConfig(t *testing.T, dir string) *Config {
	t.Helper()
	return &Config{
		CACert: writeWeakCA(t, dir, testScalar),
		CRL: CRLConfig{
			Number:          7,
			NextUpdateHours: 48,
			Revoked: []RevokedConfig{
				{Serial: "0xdeadbeef", Reason: 1},
				{Serial: "1a2b3c", Reason: 4, RevocationTime: "2026-01-02T03:04:05Z"},
			},
		},
	}
}

func TestSignCRLToFile(t *testing.T) {
	dir := t.TempDir()
	cfg := crlConfig(t, dir)
	out := filepath.Join(dir, "sub", "leaf.crl")

	var w bytes.Buffer
	if err := signCRL(cfg, out, &w); err != nil {
		t.Fatalf("signCRL: %v\n%s", err, w.String())
	}
	for _, want := range []string{
		"Recovered key:  d = 3", "Number:         7", "Revoked:        2",
		"deadbeef  reason 1", "1a2b3c  reason 4  2026-01-02T03:04:05Z",
		"[ OK ] CRL signature verifies", "crl:      " + out,
	} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("output missing %q:\n%s", want, w.String())
		}
	}
	if strings.Contains(w.String(), "[FAIL]") {
		t.Errorf("unexpected failure:\n%s", w.String())
	}

	crl := parsePEMCRL(t, out)
	if err := crl.CheckSignatureFrom(mustReadCert(t, cfg.CACert)); err != nil {
		t.Errorf("CRL signature: %v", err)
	}
	if crl.Number.Int64() != 7 || len(crl.RevokedCertificateEntries) != 2 {
		t.Errorf("number %s, %d entries", crl.Number, len(crl.RevokedCertificateEntries))
	}
	if got := crl.NextUpdate.Sub(crl.ThisUpdate); got != 48*time.Hour {
		t.Errorf("validity %s, want 48h", got)
	}
}

func TestSignCRLToStdout(t *testing.T) {
	dir := t.TempDir()
	cfg := crlConfig(t, dir)
	cfg.CRL.Number = 0 // default: this_update as a Unix timestamp
	cfg.CRL.NextUpdateHours = 0
	cfg.CRL.ThisUpdate = "1767315845" // 2026-01-01T23:44:05Z

	var w bytes.Buffer
	if err := signCRL(cfg, "", &w); err != nil {
		t.Fatalf("signCRL: %v", err)
	}
	block := strings.TrimSpace(w.String())
	if !strings.HasPrefix(block, "-----BEGIN X509 CRL-----") {
		t.Fatalf("stdout is not a CRL PEM:\n%s", w.String())
	}
	crl := parsePEMBytesCRL(t, w.Bytes())
	if !crl.ThisUpdate.Equal(time.Unix(1767315845, 0)) {
		t.Errorf("this_update = %s, want the configured timestamp", crl.ThisUpdate.UTC())
	}
	if crl.Number.Int64() != 1767315845 {
		t.Errorf("default CRL number = %s, want this_update as a Unix timestamp", crl.Number)
	}
	if got := crl.NextUpdate.Sub(crl.ThisUpdate); got != 24*time.Hour {
		t.Errorf("default validity %s, want 24h", got)
	}
}

func TestSignCRLConfigOutput(t *testing.T) {
	dir := t.TempDir()
	cfg := crlConfig(t, dir)
	cfg.CRL.Output = filepath.Join(dir, "configured.crl")

	if err := signCRL(cfg, "", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	parsePEMCRL(t, cfg.CRL.Output) // must exist and parse
}

func TestSignCRLWithLoadedKey(t *testing.T) {
	dir := t.TempDir()
	cfg := crlConfig(t, dir)
	cfg.CAKey = writeECKey(t, filepath.Join(dir, "ca.key"), scalarKey(t, testScalar))

	var w bytes.Buffer
	if err := signCRL(cfg, filepath.Join(dir, "k.crl"), &w); err != nil {
		t.Fatal(err)
	}
	// With a loaded key there is no recovered scalar to report.
	if strings.Contains(w.String(), "Recovered key") {
		t.Errorf("reported a recovered key despite ca_key:\n%s", w.String())
	}
}

func TestSignCRLErrors(t *testing.T) {
	dir := t.TempDir()
	caPath := writeWeakCA(t, dir, testScalar)
	file := writePEM(t, filepath.Join(dir, "file"), "X", nil)

	cases := map[string]struct {
		cfg  *Config
		out  string
		want string
	}{
		"no ca_cert":          {&Config{}, "", "ca_cert is required"},
		"missing ca_cert":     {&Config{CACert: filepath.Join(dir, "none.pem")}, "", "ca_cert"},
		"bad this_update":     {&Config{CACert: caPath, CRL: CRLConfig{ThisUpdate: "whenever"}}, "", "this_update"},
		"bad serial":          {&Config{CACert: caPath, CRL: CRLConfig{Revoked: []RevokedConfig{{Serial: "nothex"}}}}, "", "invalid serial"},
		"bad revocation_time": {&Config{CACert: caPath, CRL: CRLConfig{Revoked: []RevokedConfig{{Serial: "1", RevocationTime: "soon"}}}}, "", "revocation_time"},
		"no crlSign": {&Config{CACert: writeCA(t, filepath.Join(t.TempDir()), testScalar, func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageCertSign
		})}, "", "sign CRL"},
		"mkdir fails": {&Config{CACert: caPath}, filepath.Join(file, "x.crl"), ""},
		"write fails": {&Config{CACert: caPath}, dir, ""},
	}
	for name, tc := range cases {
		if err := signCRL(tc.cfg, tc.out, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
}

func TestCRLCheckFailures(t *testing.T) {
	dir := t.TempDir()
	cfg := crlConfig(t, dir)
	if err := signCRL(cfg, filepath.Join(dir, "a.crl"), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	crl := parsePEMCRL(t, filepath.Join(dir, "a.crl"))

	// Verify against an unrelated CA: signature and key ID both mismatch.
	other := mustReadCert(t, writeWeakCA(t, t.TempDir(), 5))
	var w bytes.Buffer
	err := crlCheck(&w, crl, other)
	if err == nil || !strings.Contains(err.Error(), "checks failed") {
		t.Fatalf("expected failed checks, got %v", err)
	}
	for _, want := range []string{"[FAIL] CRL signature", "[FAIL] CRL authority key ID"} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("output missing %q:\n%s", want, w.String())
		}
	}
}

func TestParseSerial(t *testing.T) {
	for in, want := range map[string]int64{"ff": 255, "0xFF": 255, "0X10": 16, " a ": 10, "0": 0} {
		got, err := parseSerial(in)
		if err != nil || got.Int64() != want {
			t.Errorf("parseSerial(%q) = %v, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "nothex", "0x", "-1"} {
		if _, err := parseSerial(in); err == nil {
			t.Errorf("parseSerial(%q): expected error", in)
		}
	}
}
