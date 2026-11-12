package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
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
	cfg.Leaf.ValidityHours = int(maxValidity.Hours()) + 1
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
		{"cn and omit", func(t *testing.T, dir string, cfg *Config) {
			cfg.Leaf.CommonName, cfg.Leaf.OmitCommonName = "poc.example", true
		}, "must be empty"},
		{"not before", func(t *testing.T, dir string, cfg *Config) { cfg.Leaf.NotBefore = "yesterday" }, "invalid not_before"},
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
		Province:              []string{"Berlin"},
		Locality:              []string{"Berlin"},
		SerialNumber:          "HRB 12345",
		BusinessCategory:      "Private Organization",
		JurisdictionCountry:   "DE",
		JurisdictionProvince:  "Berlin",
		JurisdictionLocality:  "Berlin",
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
	if got := leaf.Subject.OrganizationalUnit; len(got) != 1 || got[0] != "Lab" {
		t.Errorf("OU = %q", got)
	}
	if s := leaf.Subject; len(s.Province) != 1 || len(s.Locality) != 1 || s.SerialNumber != "HRB 12345" {
		t.Errorf("subject = %s", s)
	}
	ev := map[string]string{}
	for _, a := range leaf.Subject.Names {
		ev[a.Type.String()] = fmt.Sprint(a.Value)
	}
	for oid, want := range map[string]string{
		"2.5.4.15":                 "Private Organization",
		"1.3.6.1.4.1.311.60.2.1.1": "Berlin",
		"1.3.6.1.4.1.311.60.2.1.2": "Berlin",
		"1.3.6.1.4.1.311.60.2.1.3": "DE",
	} {
		if ev[oid] != want {
			t.Errorf("subject %s = %q, want %q", oid, ev[oid], want)
		}
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
	subj := parsePEMCerts(t, out.Bytes())[0].Subject
	if subj.CommonName != "ops@poc.example" {
		t.Errorf("CN = %q", subj.CommonName)
	}
	// Only configured attributes appear; the BRs forbid OU in TLS certificates.
	if len(subj.Names) != 1 {
		t.Errorf("subject = %s, want CN only", subj)
	}
}

func TestLeafOmitCommonName(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.Leaf = LeafConfig{OmitCommonName: true, DNSNames: []string{"poc.example"}}

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "chain: poc.example -> ") {
		t.Errorf("chain not named after the SAN:\n%s", out.String())
	}
	leaf, err := readCert(cfg.Output.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Subject.Names) != 0 {
		t.Errorf("subject = %s, want empty", leaf.Subject)
	}
}

func TestLeafBackdated(t *testing.T) {
	notBefore := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second).UTC()
	dir := t.TempDir()
	ca := writeCA(t, dir, testScalar, func(c *x509.Certificate) { c.NotBefore = notBefore.Add(-time.Hour) })
	cfg := testConfig(dir, ca)
	cfg.Leaf.NotBefore = notBefore.Format(time.RFC3339)

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if want := "[ OK ] chain verification against CA certificate (intermediate used as trust anchor, offline) at " + cfg.Leaf.NotBefore; !strings.Contains(out.String(), want) {
		t.Errorf("output missing %q:\n%s", want, out.String())
	}
	leaf, err := readCert(cfg.Output.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(notBefore.Add(24*time.Hour)) {
		t.Errorf("validity = %s - %s, want from %s", leaf.NotBefore, leaf.NotAfter, notBefore)
	}
}

func TestLeafDefaults(t *testing.T) {
	for _, tc := range []struct {
		org    []string
		policy string
	}{{nil, policyDV}, {[]string{"Org"}, policyOV}} {
		dir := t.TempDir()
		caPath := writeWeakCA(t, dir, testScalar)
		cfg := testConfig(dir, caPath)
		cfg.Leaf.Organization = tc.org

		var out bytes.Buffer
		if err := run(cfg, runOptions{show: true}, &out); err != nil {
			t.Fatal(err)
		}
		leaf := parsePEMCerts(t, out.Bytes())[0]
		if len(leaf.Policies) != 1 || leaf.Policies[0].String() != tc.policy {
			t.Errorf("org %q: policies = %v, want %s", tc.org, leaf.Policies, tc.policy)
		}
		ca, err := readCert(caPath)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("http://crt.sh/?d=%X", sha256.Sum256(ca.Raw))
		if got := leaf.IssuingCertificateURL; len(got) != 1 || got[0] != want {
			t.Errorf("CA issuers = %q, want %q", got, want)
		}
	}
}

func TestLeafInheritsCAPolicies(t *testing.T) {
	dir := t.TempDir()
	caPath := writeCA(t, dir, testScalar, func(c *x509.Certificate) {
		for _, s := range []string{"2.23.140.1.1", "1.3.6.1.4.1.50977.1.0.1", anyPolicy} {
			oid, err := x509.ParseOID(s)
			if err != nil {
				t.Fatal(err)
			}
			c.Policies = append(c.Policies, oid)
		}
	})
	cfg := testConfig(dir, caPath)
	cfg.Leaf.Organization = []string{"Org"}

	var out bytes.Buffer
	if err := run(cfg, runOptions{show: true}, &out); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(parsePEMCerts(t, out.Bytes())[0].Policies); got != "[2.23.140.1.1 1.3.6.1.4.1.50977.1.0.1]" {
		t.Errorf("policies = %s", got)
	}
}
