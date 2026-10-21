package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.Leaf.ValidityHours = 24 * 30
	if err := run(cfg, runOptions{show: true}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected validity cap error")
	}
}

func TestCLISANsInLeaf(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
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

func TestIssueErrors(t *testing.T) {
	cases := []struct {
		name string
		mod  func(t *testing.T, dir string, cfg *Config)
		want string
	}{
		{"no ca", func(t *testing.T, dir string, cfg *Config) { cfg.CACert = "" }, "ca_cert is required"},
		{"no names", func(t *testing.T, dir string, cfg *Config) { cfg.Leaf = LeafConfig{} }, "at least one SAN"},
		{"missing ca", func(t *testing.T, dir string, cfg *Config) { cfg.CACert = filepath.Join(dir, "missing.pem") }, "ca_cert:"},
		{"rsa ca", func(t *testing.T, dir string, cfg *Config) { cfg.CACert = writeRSACA(t, dir) }, "expected ECDSA public key"},
		{"missing ca key", func(t *testing.T, dir string, cfg *Config) { cfg.CAKey = filepath.Join(dir, "missing.key") }, "ca_key:"},
		{"wrong ca key", func(t *testing.T, dir string, cfg *Config) {
			cfg.CAKey = writeECKey(t, filepath.Join(dir, "ca.key"), scalarKey(t, testScalar+2))
		}, "does not match"},
		{"missing root", func(t *testing.T, dir string, cfg *Config) { cfg.RootCert = filepath.Join(dir, "missing.pem") }, "root_cert:"},
		{"key type", func(t *testing.T, dir string, cfg *Config) { cfg.Leaf.KeyType = "dsa" }, "unknown key_type"},
		{"ip", func(t *testing.T, dir string, cfg *Config) { cfg.Leaf.IPAddresses = []string{"nope"} }, "invalid ip address"},
		{"uri", func(t *testing.T, dir string, cfg *Config) { cfg.Leaf.URIs = []string{"no-scheme"} }, "invalid uri"},
		{"eku", func(t *testing.T, dir string, cfg *Config) { cfg.Leaf.ExtKeyUsage = []string{"bogus"} }, "unknown ext_key_usage"},
		{"policy", func(t *testing.T, dir string, cfg *Config) { cfg.Leaf.PolicyOIDs = []string{"1.x"} }, "invalid policy oid"},
		{"sign", func(t *testing.T, dir string, cfg *Config) {
			cfg.Leaf.EmailAddresses = []string{"\u00fc@a.example"} // not an IA5String
		}, "sign leaf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
			tc.mod(t, dir, cfg)
			err := run(cfg, runOptions{show: true}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestIssueWithCAKey(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.CAKey = writeECKey(t, filepath.Join(dir, "ca.key"), scalarKey(t, testScalar))

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "Recovered key") {
		t.Errorf("key was loaded from file but output claims recovery:\n%s", out.String())
	}
}

func TestRecoverScalarUnsupportedCurve(t *testing.T) {
	// CurveParams is not one of the named curves ParseRawPrivateKey accepts.
	pub := &ecdsa.PublicKey{Curve: elliptic.P256().Params()}
	if _, _, err := recoverScalar(pub, 1); err == nil {
		t.Fatal("expected error for unsupported curve")
	}
}

func TestGenerateKey(t *testing.T) {
	for keyType, want := range map[string]string{
		"":           "ECDSA P-256",
		"ecdsa-p256": "ECDSA P-256",
		"ecdsa-p384": "ECDSA P-384",
		"rsa-2048":   "RSA 2048",
		"rsa-3072":   "RSA 3072",
	} {
		k, err := generateKey(keyType)
		if err != nil {
			t.Fatalf("%q: %v", keyType, err)
		}
		if got := keyDescription(k.Public()); got != want {
			t.Errorf("%q: got %s, want %s", keyType, got, want)
		}
	}
}

func TestLeafAllOptions(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.Output.Chain = ""
	cfg.Leaf = LeafConfig{
		CommonName:            "poc",
		DNSNames:              []string{"poc.example"},
		EmailAddresses:        []string{"ops@poc.example"},
		URIs:                  []string{"https://poc.example/"},
		Organization:          []string{"Org"},
		OrganizationalUnit:    []string{"Lab"},
		Country:               []string{"DE"},
		ValidityHours:         48,
		KeyType:               "rsa-2048",
		ExtKeyUsage:           []string{"serverAuth", "clientAuth"},
		PolicyOIDs:            []string{"2.23.140.1.2.1"},
		CRLDistributionPoints: []string{"http://crl.poc.example/ca.crl"},
		OCSPServer:            []string{"http://ocsp.poc.example"},
		IssuingCertificateURL: []string{"http://poc.example/ca.crt"},
	}

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		"RSA 2048", "keyEncipherment", "serverAuth, clientAuth", "Policy:         2.23.140.1.2.1",
		"email:ops@poc.example", "URI:https://poc.example/", "CRL:            http://crl.poc.example/ca.crl",
		"OCSP:           http://ocsp.poc.example", "CA issuers:     http://poc.example/ca.crt",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out.String(), "\n  chain: ") {
		t.Error("chain output listed although output.chain is empty")
	}

	leaf, err := readCert(cfg.Output.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.Subject.OrganizationalUnit; len(got) != 2 || got[0] != "Lab" || got[1] != pocMarker {
		t.Errorf("OU = %q", got)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != 48*time.Hour+5*time.Minute {
		t.Errorf("validity = %s", got)
	}
}

func TestLeafCommonNameFallback(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.Leaf = LeafConfig{EmailAddresses: []string{"ops@poc.example"}}

	var out bytes.Buffer
	if err := run(cfg, runOptions{show: true}, &out); err != nil {
		t.Fatal(err)
	}
	if cn := parsePEMCerts(t, out.Bytes())[0].Subject.CommonName; cn != "ops@poc.example" {
		t.Errorf("CN = %q", cn)
	}
}
