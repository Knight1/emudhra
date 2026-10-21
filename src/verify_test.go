package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestDistrustedScalarStillVerifies uses the scalar of a real eMudhra
// intermediate, whose public key newer Go versions distrust in x509.Verify.
func TestDistrustedScalarStillVerifies(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 4))

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[ OK ] chain verification") || !strings.Contains(out.String(), "[INFO] Go x509.Verify") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
}

func TestVerifyChainRejects(t *testing.T) {
	now := time.Now()
	caTmpl := func(cn string, eku ...x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			ExtKeyUsage:           eku,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey, otherKey, leafKey := key(), key(), key()
	ca := newTestCert(t, caTmpl("CA"), caTmpl("CA"), &caKey.PublicKey, caKey)
	other := newTestCert(t, caTmpl("CA"), caTmpl("CA"), &otherKey.PublicKey, otherKey)
	csCA := newTestCert(t, caTmpl("CS CA", x509.ExtKeyUsageCodeSigning), caTmpl("CS CA"), &caKey.PublicKey, caKey)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Minute),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"poc.example"},
	}
	leaf := newTestCert(t, leafTmpl, ca, &leafKey.PublicKey, caKey)
	csLeaf := newTestCert(t, leafTmpl, csCA, &leafKey.PublicKey, caKey)

	if err := verifyChain([]*x509.Certificate{leaf, ca}, now); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	cases := map[string]struct {
		chain []*x509.Certificate
		now   time.Time
	}{
		"wrong signer":   {[]*x509.Certificate{leaf, other}, now},
		"expired":        {[]*x509.Certificate{leaf, ca}, now.Add(2 * time.Hour)},
		"not yet valid":  {[]*x509.Certificate{leaf, ca}, now.Add(-2 * time.Hour)},
		"name mismatch":  {[]*x509.Certificate{csLeaf, ca}, now},
		"eku not nested": {[]*x509.Certificate{csLeaf, csCA}, now},
	}
	for name, tc := range cases {
		if err := verifyChain(tc.chain, tc.now); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestCheckReportsFailures(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	res, err := issue(cfg)
	if err != nil {
		t.Fatal(err)
	}
	other, err := readCert(writeCA(t, t.TempDir(), testScalar+2, func(c *x509.Certificate) {
		c.Subject.CommonName = "Other CA"
	}))
	if err != nil {
		t.Fatal(err)
	}
	res.ca = other
	if res.leafKey, err = generateKey(""); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = check(&out, cfg, res)
	if err == nil {
		t.Fatal("expected failed checks")
	}
	for _, want := range []string{"leaf signature", "generated leaf key", "authority key ID", "chain verification"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	if !strings.Contains(out.String(), "[FAIL]") || !strings.Contains(out.String(), "[INFO] Go x509.Verify rejects the chain") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
}

func TestVerifyChainPathLen(t *testing.T) {
	now := time.Now()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	for _, tc := range []struct {
		pathLen int
		ok      bool
	}{{0, false}, {1, true}} {
		rootKey, subKey, leafKey := key(), key(), key()
		rootTmpl := caTemplate("Root")
		rootTmpl.MaxPathLen, rootTmpl.MaxPathLenZero = tc.pathLen, tc.pathLen == 0
		root := newTestCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
		sub := newTestCert(t, caTemplate("Sub"), root, &subKey.PublicKey, rootKey)
		leaf := newTestCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "leaf"},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Minute),
		}, sub, &leafKey.PublicKey, subKey)

		err := verifyChain([]*x509.Certificate{leaf, sub, root}, now)
		if (err == nil) != tc.ok {
			t.Errorf("pathLen %d: err = %v, want ok = %t", tc.pathLen, err, tc.ok)
		}
	}
}

func TestAllowsExtKeyUsages(t *testing.T) {
	server := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cases := []struct {
		name   string
		ca     *x509.Certificate
		usages []x509.ExtKeyUsage
		want   bool
	}{
		{"no eku", &x509.Certificate{}, server, true},
		{"unknown eku only", &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3}}}, server, false},
		{"any", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}, server, true},
		{"second matches", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}, server, true},
		{"mismatch", &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}, server, false},
	}
	for _, tc := range cases {
		if got := allowsExtKeyUsages(tc.ca, tc.usages); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}
