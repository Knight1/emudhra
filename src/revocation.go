package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// oneCRLFile is the name of the cached, filtered OneCRL inside the
// revocation directory.
const oneCRLFile = "onecrl.json"

// oneCRLRecord is one entry of Mozilla's OneCRL. It blocks a certificate
// either by issuer and serial number or by subject and SHA-256 hash of the
// public key; all values are base64-encoded DER.
type oneCRLRecord struct {
	ID           string `json:"id"`
	IssuerName   string `json:"issuerName,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
	Subject      string `json:"subject,omitempty"`
	PubKeyHash   string `json:"pubKeyHash,omitempty"`
	Details      struct {
		Bug string `json:"bug,omitempty"`
	} `json:"details"`
}

// oneCRL is the body of the OneCRL records endpoint.
type oneCRL struct {
	Data []oneCRLRecord `json:"data"`
}

// b64 decodes s and returns nil for invalid input, which never matches.
func b64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// matches reports whether r blocks c.
func (r oneCRLRecord) matches(c *x509.Certificate) bool {
	if r.IssuerName != "" {
		// OneCRL serials are DER integer contents and may have a leading zero.
		return bytes.Equal(b64(r.IssuerName), c.RawIssuer) &&
			new(big.Int).SetBytes(b64(r.SerialNumber)).Cmp(c.SerialNumber) == 0
	}
	hash := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return bytes.Equal(b64(r.Subject), c.RawSubject) && bytes.Equal(b64(r.PubKeyHash), hash[:])
}

// concerns reports whether r refers to one of certs by issuer or subject,
// which is what is kept when caching OneCRL.
func (r oneCRLRecord) concerns(certs []*x509.Certificate) bool {
	for _, c := range certs {
		if bytes.Equal(b64(r.IssuerName), c.RawIssuer) || bytes.Equal(b64(r.Subject), c.RawSubject) {
			return true
		}
	}
	return false
}

// crlCacheName maps a CRL URL to a file name, e.g.
// "http://crl.emsign.com/?roottlscag3.crl" -> "crl.emsign.com_roottlscag3.crl".
func crlCacheName(url string) string {
	url = strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
	name := strings.Join(strings.FieldsFunc(url, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-')
	}), "_")
	if !strings.HasSuffix(name, ".crl") {
		name += ".crl"
	}
	return name
}

// verifyCRL parses der and checks that it is signed by one of issuers.
func verifyCRL(der []byte, issuers []*x509.Certificate) (*x509.RevocationList, error) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	for _, iss := range issuers {
		if bytes.Equal(iss.RawSubject, crl.RawIssuer) && crl.CheckSignatureFrom(iss) == nil {
			return crl, nil
		}
	}
	return nil, fmt.Errorf("CRL issued by %q is not signed by any trusted root", crl.Issuer)
}

var reasonNames = map[int]string{
	0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL",
	9: "privilegeWithdrawn", 10: "aACompromise",
}

func reasonName(code int) string {
	if name, ok := reasonNames[code]; ok {
		return name
	}
	return fmt.Sprintf("reason %d", code)
}

// checkRevocation reports the status of ca in the cached CRLs from its CRL
// distribution points and in the cached OneCRL. Being revoked is expected
// for the compromised intermediates and therefore informational; missing
// or invalid cache data is an error.
func checkRevocation(w io.Writer, ca *x509.Certificate, roots []*x509.Certificate, dir string, now time.Time) error {
	fmt.Fprintf(w, "Revocation (cache: %s)\n", dir)
	if len(ca.CRLDistributionPoints) == 0 {
		fmt.Fprintln(w, "  [INFO] CA certificate has no CRL distribution point")
	}
	for _, url := range ca.CRLDistributionPoints {
		der, err := os.ReadFile(filepath.Join(dir, crlCacheName(url)))
		if err != nil {
			return fmt.Errorf("CRL %s not cached, run -update-revocation: %w", url, err)
		}
		crl, err := verifyCRL(der, roots)
		if err != nil {
			return fmt.Errorf("CRL %s: %w", url, err)
		}
		if !bytes.Equal(crl.RawIssuer, ca.RawIssuer) {
			return fmt.Errorf("CRL %s: issued by %q, not by the CA's issuer %q", url, crl.Issuer, ca.Issuer)
		}
		status := "not revoked"
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(ca.SerialNumber) == 0 {
				status = fmt.Sprintf("REVOKED at %s, reason %s",
					e.RevocationTime.UTC().Format(time.RFC3339), reasonName(e.ReasonCode))
			}
		}
		stale := ""
		if now.After(crl.NextUpdate) {
			stale = ", STALE"
		}
		fmt.Fprintf(w, "  [INFO] CRL %s (next update %s%s): %s\n",
			url, crl.NextUpdate.UTC().Format(time.RFC3339), stale, status)
	}

	data, err := os.ReadFile(filepath.Join(dir, oneCRLFile))
	if err != nil {
		return fmt.Errorf("OneCRL not cached, run -update-revocation: %w", err)
	}
	var list oneCRL
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("OneCRL: %w", err)
	}
	status := "not listed"
	for _, r := range list.Data {
		if r.matches(ca) {
			status = "LISTED (" + r.Details.Bug + ")"
		}
	}
	fmt.Fprintf(w, "  [INFO] OneCRL: %s\n", status)
	return nil
}
