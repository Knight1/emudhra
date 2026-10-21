package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func describe(w io.Writer, title string, c *x509.Certificate) {
	fp := sha256.Sum256(c.Raw)
	fmt.Fprintln(w, title)
	fmt.Fprintf(w, "  Subject:        %s\n", c.Subject)
	fmt.Fprintf(w, "  Issuer:         %s\n", c.Issuer)
	fmt.Fprintf(w, "  Serial:         %s\n", hex.EncodeToString(c.SerialNumber.Bytes()))
	fmt.Fprintf(w, "  Not before:     %s\n", c.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  Not after:      %s\n", c.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  Public key:     %s\n", keyDescription(c.PublicKey))
	fmt.Fprintf(w, "  Signature alg:  %s\n", c.SignatureAlgorithm)
	fmt.Fprintf(w, "  CA:             %t\n", c.IsCA)
	fmt.Fprintf(w, "  Key usage:      %s\n", strings.Join(keyUsageNames(c.KeyUsage), ", "))
	if len(c.ExtKeyUsage) > 0 {
		names := make([]string, len(c.ExtKeyUsage))
		for i, u := range c.ExtKeyUsage {
			names[i] = extKeyUsageName(u)
		}
		fmt.Fprintf(w, "  Ext key usage:  %s\n", strings.Join(names, ", "))
	}
	if sans := subjectAltNames(c); len(sans) > 0 {
		fmt.Fprintf(w, "  SANs:           %s\n", strings.Join(sans, ", "))
	}
	for _, oid := range c.Policies {
		fmt.Fprintf(w, "  Policy:         %s\n", oid)
	}
	if len(c.SubjectKeyId) > 0 {
		fmt.Fprintf(w, "  Subject key ID: %x\n", c.SubjectKeyId)
	}
	if len(c.AuthorityKeyId) > 0 {
		fmt.Fprintf(w, "  Auth key ID:    %x\n", c.AuthorityKeyId)
	}
	for _, u := range c.CRLDistributionPoints {
		fmt.Fprintf(w, "  CRL:            %s\n", u)
	}
	for _, u := range c.OCSPServer {
		fmt.Fprintf(w, "  OCSP:           %s\n", u)
	}
	for _, u := range c.IssuingCertificateURL {
		fmt.Fprintf(w, "  CA issuers:     %s\n", u)
	}
	fmt.Fprintf(w, "  SHA-256:        %s\n", strings.ToUpper(hex.EncodeToString(fp[:])))
}

func subjectAltNames(c *x509.Certificate) []string {
	var sans []string
	for _, n := range c.DNSNames {
		sans = append(sans, "DNS:"+n)
	}
	for _, ip := range c.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, e := range c.EmailAddresses {
		sans = append(sans, "email:"+e)
	}
	for _, u := range c.URIs {
		sans = append(sans, "URI:"+u.String())
	}
	return sans
}

func keyDescription(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return "RSA " + strconv.Itoa(k.N.BitLen())
	}
	return fmt.Sprintf("%T", pub)
}

func keyUsageNames(ku x509.KeyUsage) []string {
	names := []string{"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment",
		"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"}
	var out []string
	for i, n := range names {
		if ku&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return out
}

func extKeyUsageName(u x509.ExtKeyUsage) string {
	for name, v := range extKeyUsages {
		if v == u {
			return name
		}
	}
	return fmt.Sprintf("EKU(%d)", u)
}
