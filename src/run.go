package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type runOptions struct {
	show  bool // print only the certificate; no files, no checks
	chain bool // also print the complete chain as PEM
	json  bool // print only the chain as an RFC 6962 add-chain request

	revocation    bool   // check the issuing CA against the revocation cache
	rootsDir      string // roots that sign the cached CRLs
	revocationDir string // revocation cache written by -update-revocation
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

	// With -json, only the JSON is printed so it can be piped to a CT log.
	text := w
	if opts.json {
		text = io.Discard
	}

	describe(text, "Issuing CA", res.ca)
	if res.scalar != 0 {
		fmt.Fprintf(text, "  Recovered key:  d = %d\n", res.scalar)
	}
	fmt.Fprintln(text)
	describe(text, "Leaf certificate", res.leaf)
	fmt.Fprintln(text)

	err = check(text, res)
	if err == nil && opts.revocation {
		fmt.Fprintln(text)
		err = revocationReport(text, res.ca, opts)
	}
	printOutputs(text, cfg)
	if err != nil {
		return err
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

// revocationReport checks ca against the cached CRLs and OneCRL.
func revocationReport(w io.Writer, ca *x509.Certificate, opts runOptions) error {
	roots, err := readCertDir(opts.rootsDir)
	if err == nil {
		err = checkRevocation(w, ca, roots, opts.revocationDir, time.Now())
	}
	if err != nil {
		return fmt.Errorf("revocation: %w", err)
	}
	return nil
}

func printOutputs(w io.Writer, cfg *Config) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Output")
	fmt.Fprintf(w, "  cert:  %s\n  key:   %s\n", cfg.Output.Cert, cfg.Output.Key)
	if cfg.Output.Chain != "" {
		fmt.Fprintf(w, "  chain: %s\n", cfg.Output.Chain)
	}
	fmt.Fprintln(w, "\nNote: the issuing CA was revoked with reason caCompromise; revocation-checking clients should reject this chain.")
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
