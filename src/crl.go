package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// signCRL recovers the compromised CA key and signs a CRL from cfg.CRL,
// demonstrating that the key can forge revocation lists as well as leaf
// certificates. out overrides cfg.CRL.Output; when both are empty the CRL PEM
// is written to w so it can be piped. Otherwise a report is written to w and
// the CRL PEM to the output file.
func signCRL(cfg *Config, out string, w io.Writer) error {
	if cfg.CACert == "" {
		return errors.New("ca_cert is required")
	}
	ca, caKey, scalar, err := loadCA(cfg)
	if err != nil {
		return err
	}
	tmpl, err := crlTemplate(&cfg.CRL, time.Now())
	if err != nil {
		return err
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		return fmt.Errorf("sign CRL: %w", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})

	if out == "" {
		out = cfg.CRL.Output
	}
	if out == "" {
		_, err := w.Write(crlPEM)
		return err
	}

	// CreateRevocationList output always parses.
	crl, _ := x509.ParseRevocationList(der)

	// Write the file before the checks so the CRL is always produced.
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, crlPEM, 0o644); err != nil {
		return err
	}

	describe(w, "Issuing CA", ca)
	if scalar != 0 {
		fmt.Fprintf(w, "  Recovered key:  d = %d\n", scalar)
	}
	fmt.Fprintln(w)
	describeCRL(w, crl)
	fmt.Fprintln(w)
	err = crlCheck(w, crl, ca)
	fmt.Fprintf(w, "\nOutput\n  crl:      %s\n", out)
	fmt.Fprintln(w, "\nNote: this CRL is signed by the compromised, now revoked CA key; a genuine CA would never issue it.")
	return err
}

// crlTemplate builds a RevocationList from cc. Timestamps default to now, the
// CRL number to this_update as a Unix timestamp, and the validity to 24h.
func crlTemplate(cc *CRLConfig, now time.Time) (*x509.RevocationList, error) {
	thisUpdate := now
	if cc.ThisUpdate != "" {
		t, err := parseTime(cc.ThisUpdate)
		if err != nil {
			return nil, fmt.Errorf("crl this_update: %w", err)
		}
		thisUpdate = t
	}
	hours := 24
	if cc.NextUpdateHours > 0 {
		hours = cc.NextUpdateHours
	}
	number := big.NewInt(cc.Number)
	if cc.Number == 0 {
		number = big.NewInt(thisUpdate.Unix())
	}
	tmpl := &x509.RevocationList{
		Number:     number,
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(time.Duration(hours) * time.Hour),
	}
	for _, r := range cc.Revoked {
		serial, err := parseSerial(r.Serial)
		if err != nil {
			return nil, err
		}
		revTime := thisUpdate
		if r.RevocationTime != "" {
			t, err := parseTime(r.RevocationTime)
			if err != nil {
				return nil, fmt.Errorf("crl revocation_time: %w", err)
			}
			revTime = t
		}
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revTime,
			ReasonCode:     r.Reason,
		})
	}
	return tmpl, nil
}

// crlCheck verifies the signed CRL against the issuing CA.
func crlCheck(w io.Writer, crl *x509.RevocationList, ca *x509.Certificate) error {
	rep := &reporter{w: w}
	fmt.Fprintln(w, "Checks")
	rep.report("CRL signature verifies under CA public key", crl.CheckSignatureFrom(ca))
	rep.report("CRL authority key ID matches CA subject key ID", func() error {
		if !bytes.Equal(crl.AuthorityKeyId, ca.SubjectKeyId) {
			return fmt.Errorf("AKI %x != SKI %x", crl.AuthorityKeyId, ca.SubjectKeyId)
		}
		return nil
	}())
	return rep.err()
}

func describeCRL(w io.Writer, crl *x509.RevocationList) {
	fmt.Fprintln(w, "CRL")
	fmt.Fprintf(w, "  Issuer:         %s\n", crl.Issuer)
	fmt.Fprintf(w, "  Number:         %s\n", crl.Number)
	fmt.Fprintf(w, "  This update:    %s\n", crl.ThisUpdate.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  Next update:    %s\n", crl.NextUpdate.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  Signature alg:  %s\n", crl.SignatureAlgorithm)
	// CreateRevocationList always sets the authority key ID.
	fmt.Fprintf(w, "  Auth key ID:    %x\n", crl.AuthorityKeyId)
	fmt.Fprintf(w, "  Revoked:        %d\n", len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		fmt.Fprintf(w, "    %s  reason %d  %s\n",
			hex.EncodeToString(e.SerialNumber.Bytes()), e.ReasonCode, e.RevocationTime.UTC().Format(time.RFC3339))
	}
}
