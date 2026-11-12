package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

const (
	maxValidity      = 398 * 24 * time.Hour
	defaultMaxScalar = 1 << 16
	policyDV         = "2.23.140.1.2.1"
	policyOV         = "2.23.140.1.2.2"
	anyPolicy        = "2.5.29.32.0"
)

type issued struct {
	ca      *x509.Certificate
	root    *x509.Certificate
	scalar  uint64 // 0 if the CA key was loaded from a file
	leaf    *x509.Certificate
	leafKey crypto.Signer
	scts    []sctResult // empty without ct_logs
	precert []byte      // DER; nil without ct_logs
}

func issue(cfg *Config) (*issued, error) {
	ca, caKey, scalar, err := loadCA(cfg)
	if err != nil {
		return nil, err
	}
	res := &issued{ca: ca, scalar: scalar}

	if cfg.RootCert != "" {
		if res.root, err = readCert(cfg.RootCert); err != nil {
			return nil, fmt.Errorf("root_cert: %w", err)
		}
	}

	res.leafKey, err = generateKey(cfg.Leaf.KeyType)
	if err != nil {
		return nil, err
	}
	tmpl, err := leafTemplate(&cfg.Leaf, ca, res.leafKey)
	if err != nil {
		return nil, err
	}

	if len(cfg.CTLogs) > 0 {
		if res.scts, res.precert, err = addSCTs(tmpl, cfg.CTLogs, ca, res.root, res.leafKey.Public(), caKey); err != nil {
			return nil, err
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, res.leafKey.Public(), caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	// The DER comes straight from CreateCertificate, so parsing cannot fail.
	res.leaf, _ = x509.ParseCertificate(der)
	return res, nil
}

// loadCA loads the compromised intermediate and its ECDSA private key. The
// key is recovered from the public certificate by brute force unless ca_key
// is configured. scalar is the recovered private scalar, or 0 when the key
// was loaded from a file.
func loadCA(cfg *Config) (ca *x509.Certificate, caKey *ecdsa.PrivateKey, scalar uint64, err error) {
	ca, err = readCert(cfg.CACert)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ca_cert: %w", err)
	}
	caPub, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, 0, fmt.Errorf("ca_cert: expected ECDSA public key, got %T", ca.PublicKey)
	}
	if cfg.CAKey != "" {
		if caKey, err = readECKey(cfg.CAKey); err != nil {
			return nil, nil, 0, fmt.Errorf("ca_key: %w", err)
		}
	} else {
		max := cfg.MaxScalar
		if max == 0 {
			max = defaultMaxScalar
		}
		if caKey, scalar, err = recoverScalar(caPub, max); err != nil {
			return nil, nil, 0, err
		}
	}
	if !caKey.PublicKey.Equal(caPub) {
		return nil, nil, 0, errors.New("CA private key does not match CA certificate")
	}
	return ca, caKey, scalar, nil
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

func leafTemplate(lc *LeafConfig, ca *x509.Certificate, key crypto.Signer) (*x509.Certificate, error) {
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
	if cn == "" && !lc.OmitCommonName {
		for _, names := range [][]string{lc.DNSNames, lc.IPAddresses, lc.EmailAddresses} {
			if len(names) > 0 {
				cn = names[0]
				break
			}
		}
	}
	now := time.Now()
	notBefore, notAfter := now.Add(-5*time.Minute), now.Add(validity)
	if lc.NotBefore != "" {
		t, err := parseNotBefore(lc.NotBefore, now)
		if err != nil {
			return nil, err
		}
		notBefore, notAfter = t, t.Add(validity)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       lc.Organization,
			OrganizationalUnit: lc.OrganizationalUnit,
			Country:            lc.Country,
			Province:           lc.Province,
			Locality:           lc.Locality,
			SerialNumber:       lc.SerialNumber,
			ExtraNames:         evSubjectAttributes(lc),
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              lc.DNSNames,
		EmailAddresses:        lc.EmailAddresses,
		CRLDistributionPoints: lc.CRLDistributionPoints,
		OCSPServer:            lc.OCSPServer,
		IssuingCertificateURL: lc.IssuingCertificateURL,
	}
	if len(tmpl.IssuingCertificateURL) == 0 {
		// The BRs require a caIssuers URL; crt.sh serves the CA certificate.
		tmpl.IssuingCertificateURL = []string{fmt.Sprintf("http://crt.sh/?d=%X", sha256.Sum256(ca.Raw))}
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

	policies := lc.PolicyOIDs
	if len(policies) == 0 {
		// Inherit the CA's policies: the eMudhra intermediates each carry
		// one CA/B Forum OID (DV, OV, EV or code signing) and their CPS OIDs.
		for _, oid := range ca.Policies {
			if s := oid.String(); s != anyPolicy {
				policies = append(policies, s)
			}
		}
	}
	if len(policies) == 0 {
		// The BRs require a CA/B Forum policy: OV if the subject has an
		// organization, DV otherwise.
		policies = []string{policyDV}
		if len(lc.Organization) > 0 {
			policies = []string{policyOV}
		}
	}
	for _, s := range policies {
		// CreateCertificate encodes Policies; PolicyIdentifiers is ignored.
		oid, err := x509.ParseOID(s)
		if err != nil {
			return nil, fmt.Errorf("invalid policy oid %q", s)
		}
		tmpl.Policies = append(tmpl.Policies, oid)
	}
	return tmpl, nil
}

// EV Guidelines subject attributes that pkix.Name has no field for.
var (
	oidBusinessCategory     = asn1.ObjectIdentifier{2, 5, 4, 15}
	oidJurisdictionLocality = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}
	oidJurisdictionProvince = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}
	oidJurisdictionCountry  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}
)

func evSubjectAttributes(lc *LeafConfig) []pkix.AttributeTypeAndValue {
	var attrs []pkix.AttributeTypeAndValue
	for _, a := range []struct {
		oid   asn1.ObjectIdentifier
		value string
	}{
		{oidBusinessCategory, lc.BusinessCategory},
		{oidJurisdictionLocality, lc.JurisdictionLocality},
		{oidJurisdictionProvince, lc.JurisdictionProvince},
		{oidJurisdictionCountry, lc.JurisdictionCountry},
	} {
		if a.value != "" {
			attrs = append(attrs, pkix.AttributeTypeAndValue{Type: a.oid, Value: a.value})
		}
	}
	return attrs
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
