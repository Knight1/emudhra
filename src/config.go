package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	CACert    string       `json:"ca_cert"`              // PEM of the compromised intermediate
	CAKey     string       `json:"ca_key,omitempty"`     // optional; recovered from ca_cert if empty
	RootCert  string       `json:"root_cert,omitempty"`  // optional trust anchor for chain verification
	MaxScalar uint64       `json:"max_scalar,omitempty"` // brute-force bound for key recovery
	CTLogs    []CTLog      `json:"ct_logs,omitempty"`    // submit a precertificate and embed the SCTs
	Leaf      LeafConfig   `json:"leaf"`
	Output    OutputConfig `json:"output"`
}

type LeafConfig struct {
	CommonName            string   `json:"common_name"`
	OmitCommonName        bool     `json:"omit_common_name,omitempty"` // no CN; otherwise it defaults to the first SAN
	DNSNames              []string `json:"dns_names,omitempty"`
	IPAddresses           []string `json:"ip_addresses,omitempty"`
	EmailAddresses        []string `json:"email_addresses,omitempty"`
	URIs                  []string `json:"uris,omitempty"`
	Organization          []string `json:"organization,omitempty"`
	OrganizationalUnit    []string `json:"organizational_unit,omitempty"`
	Country               []string `json:"country,omitempty"`
	Province              []string `json:"province,omitempty"`
	Locality              []string `json:"locality,omitempty"`
	SerialNumber          string   `json:"serial_number,omitempty"`         // EV: registration number
	BusinessCategory      string   `json:"business_category,omitempty"`     // EV: e.g. "Private Organization"
	JurisdictionCountry   string   `json:"jurisdiction_country,omitempty"`  // EV: two-letter country code
	JurisdictionProvince  string   `json:"jurisdiction_province,omitempty"` // EV: optional
	JurisdictionLocality  string   `json:"jurisdiction_locality,omitempty"` // EV: optional
	NotBefore             string   `json:"not_before,omitempty"`            // backdate: Unix timestamp or UTC datetime
	ValidityHours         int      `json:"validity_hours,omitempty"`
	KeyType               string   `json:"key_type,omitempty"`      // ecdsa-p256 | ecdsa-p384 | rsa-2048 | rsa-3072
	ExtKeyUsage           []string `json:"ext_key_usage,omitempty"` // serverAuth | clientAuth | codeSigning | emailProtection
	PolicyOIDs            []string `json:"policy_oids,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	OCSPServer            []string `json:"ocsp_server,omitempty"`
	IssuingCertificateURL []string `json:"issuing_certificate_url,omitempty"`
}

// CTLog is a Certificate Transparency log. Key is optional: the log's
// public key as base64 DER (as in the browser log lists), used to verify
// its SCT.
type CTLog struct {
	URL string `json:"url"`
	Key string `json:"key,omitempty"`
}

type OutputConfig struct {
	Cert  string `json:"cert"`
	Key   string `json:"key"`
	Chain string `json:"chain,omitempty"`
}

// listFlag collects repeatable, comma-separated flag values such as -san
// and -ct-log.
type listFlag []string

func (s *listFlag) String() string { return strings.Join(*s, ",") }

func (s *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
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

// applySANs replaces the SANs in lc with the given CLI values. The common
// name is cleared too, so it is taken from the new SANs.
func applySANs(lc *LeafConfig, sans []string) error {
	lc.CommonName = ""
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

// notBeforeLayouts are the accepted datetime formats for not_before. Values
// without a zone are UTC.
var notBeforeLayouts = []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"}

// parseNotBefore parses a Unix timestamp in seconds or a datetime. The time
// must not be in the future, since the option is for backdating.
func parseNotBefore(s string, now time.Time) (time.Time, error) {
	t, err := parseTime(s)
	if err != nil {
		return time.Time{}, err
	}
	if t.After(now) {
		return time.Time{}, fmt.Errorf("not_before %s is in the future", t.Format(time.RFC3339))
	}
	return t, nil
}

func parseTime(s string) (time.Time, error) {
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(sec, 0).UTC(), nil
	}
	for _, layout := range notBeforeLayouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid not_before %q (use a Unix timestamp or a UTC datetime such as 2026-01-02T15:04:05Z)", s)
}
