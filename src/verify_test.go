package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
