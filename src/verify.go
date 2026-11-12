package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// check prints the result of each check to w and returns an error naming
// every failed check, so failures are visible even when w discards output.
func check(w io.Writer, res *issued) error {
	var failed []string
	report := func(name string, err error) {
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", name, err))
			fmt.Fprintf(w, "  [FAIL] %s: %v\n", name, err)
			return
		}
		fmt.Fprintf(w, "  [ OK ] %s\n", name)
	}

	fmt.Fprintln(w, "Checks")
	report("leaf signature verifies under CA public key", res.leaf.CheckSignatureFrom(res.ca))
	report("leaf certificate matches generated leaf key", func() error {
		if !publicKeysEqual(res.leaf.PublicKey, res.leafKey.Public()) {
			return errors.New("public key mismatch")
		}
		return nil
	}())
	report("leaf authority key ID matches CA subject key ID", func() error {
		if !bytes.Equal(res.leaf.AuthorityKeyId, res.ca.SubjectKeyId) {
			return fmt.Errorf("AKI %x != SKI %x", res.leaf.AuthorityKeyId, res.ca.SubjectKeyId)
		}
		return nil
	}())

	chain := chainCerts(res)
	anchor := "CA certificate (intermediate used as trust anchor, offline)"
	if res.root != nil {
		anchor = "root " + res.root.Subject.CommonName
	}
	// A backdated leaf may have expired already; verify it at its notBefore.
	at, when := time.Now(), ""
	if at.After(res.leaf.NotAfter) {
		at = res.leaf.NotBefore
		when = " at " + at.UTC().Format(time.RFC3339)
	}
	report("chain verification against "+anchor+when, verifyChain(chain, at))
	names := make([]string, len(chain))
	for i, c := range chain {
		names[i] = certName(c)
	}
	fmt.Fprintf(w, "         chain: %s\n", strings.Join(names, " -> "))

	// Informational only: Go 1.26.10 / 1.27.3 and later refuse chains that
	// contain the compromised eMudhra keys, regardless of the trust anchor.
	if err := goVerify(chain, at); err != nil {
		fmt.Fprintf(w, "  [INFO] Go x509.Verify rejects the chain: %v\n", err)
	} else {
		fmt.Fprintln(w, "  [INFO] Go x509.Verify accepts the chain")
	}

	reportSCTs(w, res, report)

	if len(failed) > 0 {
		return fmt.Errorf("checks failed: %s", strings.Join(failed, "; "))
	}
	return nil
}

// verifyChain checks chain (leaf first, trust anchor last) the way a path
// validator would, without x509.Verify and therefore without Go's built-in
// distrust list: name chaining, signatures, CA flags and key usage, path
// length, validity and extended key usage nesting. Name constraints and
// revocation are not checked.
func verifyChain(chain []*x509.Certificate, now time.Time) error {
	leaf := chain[0]
	for _, c := range chain {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return fmt.Errorf("%q is not valid at %s", c.Subject.CommonName, now.UTC().Format(time.RFC3339))
		}
	}

	for i := 0; i < len(chain)-1; i++ {
		child, parent := chain[i], chain[i+1]
		if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
			return fmt.Errorf("issuer of %q does not match subject of %q", child.Subject.CommonName, parent.Subject.CommonName)
		}
		// CheckSignatureFrom also requires parent to be a CA with keyCertSign.
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("%q is not signed by %q: %w", child.Subject.CommonName, parent.Subject.CommonName, err)
		}
		// i is the number of CA certificates between parent and the leaf.
		// Parsed certificates use MaxPathLen -1 for "no constraint".
		if parent.MaxPathLen >= 0 && i > parent.MaxPathLen {
			return fmt.Errorf("path length constraint of %q exceeded", parent.Subject.CommonName)
		}
		if !allowsExtKeyUsages(parent, leaf.ExtKeyUsage) {
			return fmt.Errorf("%q does not allow the leaf's extended key usages", parent.Subject.CommonName)
		}
	}
	return nil
}

// allowsExtKeyUsages reports whether a CA's EKU extension (if any) permits
// all of the given usages.
func allowsExtKeyUsages(ca *x509.Certificate, usages []x509.ExtKeyUsage) bool {
	if len(ca.ExtKeyUsage) == 0 && len(ca.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range usages {
		found := false
		for _, cu := range ca.ExtKeyUsage {
			if cu == u || cu == x509.ExtKeyUsageAny {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// goVerify runs the standard library verifier on chain, with the last
// certificate as the only trust anchor.
func goVerify(chain []*x509.Certificate, at time.Time) error {
	leaf := chain[0]
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	for _, c := range chain[1 : len(chain)-1] {
		inters.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: leaf.ExtKeyUsage, CurrentTime: at}
	if len(leaf.DNSNames) > 0 {
		opts.DNSName = leaf.DNSNames[0]
	}
	_, err := leaf.Verify(opts)
	return err
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ak, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ak.Equal(b)
}

// certName names a certificate by its common name, or by its first SAN if
// it has none.
func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	for _, names := range [][]string{c.DNSNames, c.EmailAddresses} {
		if len(names) > 0 {
			return names[0]
		}
	}
	if len(c.IPAddresses) > 0 {
		return c.IPAddresses[0].String()
	}
	if len(c.URIs) > 0 {
		return c.URIs[0].String()
	}
	return c.Subject.String()
}
