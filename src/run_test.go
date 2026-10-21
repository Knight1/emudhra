package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
