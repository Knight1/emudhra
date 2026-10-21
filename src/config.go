package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
