package main

import (
	"crypto/x509"
	"encoding/hex"
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
	if lc.OmitCommonName && lc.CommonName != "" {
		return errors.New("leaf.common_name must be empty when leaf.omit_common_name is set")
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

	files, err := writeOutputs(cfg, res, leafPEM)
	if err != nil {
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
	printOutputs(text, files)
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

// outFile is a file written by writeOutputs.
type outFile struct {
	label string
	path  string
	data  []byte
	mode  os.FileMode
}

func printOutputs(w io.Writer, files []outFile) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Output")
	for _, f := range files {
		fmt.Fprintf(w, "  %-9s %s\n", f.label+":", f.path)
	}
	fmt.Fprintln(w, "\nNote: the issuing CA was revoked with reason caCompromise; revocation-checking clients should reject this chain.")
}

// writeOutputs writes the configured files and returns them in order.
// output.dir receives <serial>.crt, <serial>.key and, with CT logs,
// <serial>.crt_pre (the precertificate).
func writeOutputs(cfg *Config, res *issued, leafPEM []byte) ([]outFile, error) {
	out := cfg.Output
	if (out.Cert == "" || out.Key == "") && out.Dir == "" {
		return nil, errors.New("output.cert and output.key, or output.dir, are required (or use -show)")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(res.leafKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	var files []outFile
	add := func(label, path string, data []byte, mode os.FileMode) {
		if path != "" {
			files = append(files, outFile{label, path, data, mode})
		}
	}
	add("cert", out.Cert, leafPEM, 0o644)
	add("key", out.Key, keyPEM, 0o600)
	add("chain", out.Chain, append(append([]byte{}, leafPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.ca.Raw})...), 0o644)
	if out.Dir != "" {
		base := filepath.Join(out.Dir, hex.EncodeToString(res.leaf.SerialNumber.Bytes()))
		add("cert", base+".crt", leafPEM, 0o644)
		add("key", base+".key", keyPEM, 0o600)
		if res.precert != nil {
			add("precert", base+".crt_pre", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.precert}), 0o644)
		}
	}

	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			return nil, err
		}
	}
	return files, nil
}
