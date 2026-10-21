package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssueAndCheck(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	for _, want := range []string{fmt.Sprintf("Recovered key:  d = %d", testScalar), "[ OK ] chain verification", pocMarker} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "[FAIL]") {
		t.Errorf("unexpected failure:\n%s", out.String())
	}
	for _, p := range []string{cfg.Output.Cert, cfg.Output.Key, cfg.Output.Chain} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing output %s: %v", p, err)
		}
	}
}

func TestShowOnlyWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))

	var out bytes.Buffer
	if err := run(cfg, runOptions{show: true}, &out); err != nil {
		t.Fatal(err)
	}
	certs := parsePEMCerts(t, out.Bytes())
	if len(certs) != 1 || certs[0].IsCA {
		t.Fatalf("-show should print exactly the leaf certificate, got %d certs:\n%s", len(certs), out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Errorf("-show wrote output files")
	}
}

func TestShowChain(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))

	var out bytes.Buffer
	if err := run(cfg, runOptions{show: true, chain: true}, &out); err != nil {
		t.Fatal(err)
	}
	certs := parsePEMCerts(t, out.Bytes())
	if len(certs) != 2 || certs[0].IsCA || !certs[1].IsCA {
		t.Fatalf("expected leaf + CA, got %d certs", len(certs))
	}
	if err := certs[0].CheckSignatureFrom(certs[1]); err != nil {
		t.Errorf("chain order: %v", err)
	}
}

func TestJSONAddChain(t *testing.T) {
	for _, show := range []bool{true, false} {
		dir := t.TempDir()
		cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))

		var out bytes.Buffer
		if err := run(cfg, runOptions{show: show, json: true}, &out); err != nil {
			t.Fatalf("show=%t: %v", show, err)
		}
		var req addChainRequest
		dec := json.NewDecoder(&out)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			t.Fatalf("show=%t: stdout is not add-chain JSON: %v", show, err)
		}
		if dec.More() {
			t.Errorf("show=%t: extra data after JSON", show)
		}
		if len(req.Chain) != 2 {
			t.Fatalf("show=%t: expected leaf + CA, got %d entries", show, len(req.Chain))
		}
		leaf, err := x509.ParseCertificate(req.Chain[0])
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(req.Chain[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := leaf.CheckSignatureFrom(ca); err != nil {
			t.Errorf("show=%t: chain order: %v", show, err)
		}
		if _, err := os.Stat(cfg.Output.Cert); os.IsNotExist(err) != show {
			t.Errorf("show=%t: output file written = %t", show, err == nil)
		}
	}
}

func TestRunWithRoot(t *testing.T) {
	dir := t.TempDir()
	caPath, rootPath := writeRootedCA(t, dir)
	cfg := testConfig(dir, caPath)
	cfg.RootCert = rootPath

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		"[ OK ] chain verification against root Test Root",
		"chain: poc.example -> Weak Test CA -> Test Root",
		"[INFO] Go x509.Verify accepts the chain",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := run(cfg, runOptions{show: true, chain: true}, &out); err != nil {
		t.Fatal(err)
	}
	if n := len(parsePEMCerts(t, out.Bytes())); n != 3 {
		t.Errorf("-show -chain printed %d certificates, want 3", n)
	}
}

func TestRunChainAfterChecks(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))

	var out bytes.Buffer
	if err := run(cfg, runOptions{chain: true}, &out); err != nil {
		t.Fatal(err)
	}
	text, pemPart, ok := strings.Cut(out.String(), "-----BEGIN CERTIFICATE-----")
	if !ok || !strings.Contains(text, "Checks") {
		t.Fatalf("expected checks followed by PEM chain:\n%s", out.String())
	}
	if n := len(parsePEMCerts(t, []byte("-----BEGIN CERTIFICATE-----"+pemPart))); n != 2 {
		t.Errorf("chain has %d certificates, want 2", n)
	}
}

func TestRunFailedChecks(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeCA(t, dir, testScalar, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	}))
	for _, opts := range []runOptions{{}, {json: true}} {
		var out bytes.Buffer
		err := run(cfg, opts, &out)
		if err == nil || !strings.Contains(err.Error(), "checks failed") {
			t.Fatalf("json=%t: expected failed checks, got %v", opts.json, err)
		}
		if opts.json && out.Len() != 0 {
			t.Errorf("json output printed despite failed checks: %s", out.String())
		}
	}
}

// fakeSigner is a crypto.Signer that x509 cannot marshal.
type fakeSigner struct{ crypto.Signer }

func TestWriteOutputsErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	res, err := issue(cfg)
	if err != nil {
		t.Fatal(err)
	}
	file := writePEM(t, filepath.Join(dir, "file"), "X", nil)

	cases := map[string]func(c *Config, r *issued){
		"missing paths": func(c *Config, r *issued) { c.Output = OutputConfig{} },
		"bad key type":  func(c *Config, r *issued) { r.leafKey = fakeSigner{} },
		"mkdir fails":   func(c *Config, r *issued) { c.Output.Cert = filepath.Join(file, "leaf.pem") },
		"write fails":   func(c *Config, r *issued) { c.Output.Cert = dir },
	}
	for name, mod := range cases {
		c, r := *cfg, *res
		mod(&c, &r)
		if err := writeOutputs(&c, &r, nil); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if err := run(&Config{CACert: cfg.CACert, Leaf: cfg.Leaf}, runOptions{}, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "output.cert and output.key are required") {
		t.Errorf("run without outputs: %v", err)
	}
}
