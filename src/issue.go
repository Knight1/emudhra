package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

const (
	pocMarker        = "PoC"
	maxValidity      = 7 * 24 * time.Hour
	defaultMaxScalar = 1 << 16
)

type issued struct {
	ca      *x509.Certificate
	root    *x509.Certificate
	scalar  uint64 // 0 if the CA key was loaded from a file
	leaf    *x509.Certificate
	leafKey crypto.Signer
}

func issue(cfg *Config) (*issued, error) {
	ca, err := readCert(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("ca_cert: %w", err)
	}
	caPub, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ca_cert: expected ECDSA public key, got %T", ca.PublicKey)
	}

	res := &issued{ca: ca}
	var caKey *ecdsa.PrivateKey
	if cfg.CAKey != "" {
		caKey, err = readECKey(cfg.CAKey)
		if err != nil {
			return nil, fmt.Errorf("ca_key: %w", err)
		}
	} else {
		max := cfg.MaxScalar
		if max == 0 {
			max = defaultMaxScalar
		}
		caKey, res.scalar, err = recoverScalar(caPub, max)
		if err != nil {
			return nil, err
		}
	}
	if !caKey.PublicKey.Equal(caPub) {
		return nil, errors.New("CA private key does not match CA certificate")
	}

	if cfg.RootCert != "" {
		if res.root, err = readCert(cfg.RootCert); err != nil {
			return nil, fmt.Errorf("root_cert: %w", err)
		}
	}

	res.leafKey, err = generateKey(cfg.Leaf.KeyType)
	if err != nil {
		return nil, err
	}
	tmpl, err := leafTemplate(&cfg.Leaf, res.leafKey)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, res.leafKey.Public(), caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	// The DER comes straight from CreateCertificate, so parsing cannot fail.
	res.leaf, _ = x509.ParseCertificate(der)
	return res, nil
}

// recoverScalar finds d in [1, max] such that d*G equals pub.
func recoverScalar(pub *ecdsa.PublicKey, max uint64) (*ecdsa.PrivateKey, uint64, error) {
	buf := make([]byte, (pub.Curve.Params().BitSize+7)/8)
	for d := uint64(1); d <= max; d++ {
		binary.BigEndian.PutUint64(buf[len(buf)-8:], d)
		k, err := ecdsa.ParseRawPrivateKey(pub.Curve, buf)
		if err != nil {
			return nil, 0, err
		}
		if k.PublicKey.Equal(pub) {
			return k, d, nil
		}
	}
	return nil, 0, fmt.Errorf("no private scalar <= %d matches the CA public key", max)
}

func leafTemplate(lc *LeafConfig, key crypto.Signer) (*x509.Certificate, error) {
	validity := 24 * time.Hour
	if lc.ValidityHours > 0 {
		validity = time.Duration(lc.ValidityHours) * time.Hour
	}
	if validity > maxValidity {
		return nil, fmt.Errorf("validity_hours %d exceeds PoC limit of %d", lc.ValidityHours, int(maxValidity.Hours()))
	}

	// 127-bit positive serial; rand.Read never returns an error.
	serialBytes := make([]byte, 16)
	rand.Read(serialBytes)
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)

	cn := lc.CommonName
	if cn == "" {
		for _, names := range [][]string{lc.DNSNames, lc.IPAddresses, lc.EmailAddresses} {
			if len(names) > 0 {
				cn = names[0]
				break
			}
		}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       lc.Organization,
			OrganizationalUnit: append(append([]string{}, lc.OrganizationalUnit...), pocMarker),
			Country:            lc.Country,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              lc.DNSNames,
		EmailAddresses:        lc.EmailAddresses,
		CRLDistributionPoints: lc.CRLDistributionPoints,
		OCSPServer:            lc.OCSPServer,
		IssuingCertificateURL: lc.IssuingCertificateURL,
	}
	if _, ok := key.(*rsa.PrivateKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	for _, s := range lc.IPAddresses {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip address %q", s)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	for _, s := range lc.URIs {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" {
			return nil, fmt.Errorf("invalid uri %q", s)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}

	ekus := lc.ExtKeyUsage
	if len(ekus) == 0 {
		ekus = []string{"serverAuth"}
	}
	for _, name := range ekus {
		eku, ok := extKeyUsages[name]
		if !ok {
			return nil, fmt.Errorf("unknown ext_key_usage %q", name)
		}
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, eku)
	}

	for _, s := range lc.PolicyOIDs {
		// CreateCertificate encodes Policies; PolicyIdentifiers is ignored.
		oid, err := x509.ParseOID(s)
		if err != nil {
			return nil, fmt.Errorf("invalid policy oid %q", s)
		}
		tmpl.Policies = append(tmpl.Policies, oid)
	}
	return tmpl, nil
}

var extKeyUsages = map[string]x509.ExtKeyUsage{
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
}

func generateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "", "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return nil, fmt.Errorf("unknown key_type %q", keyType)
}
