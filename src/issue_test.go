package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecoveryBound(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, 200))
	cfg.MaxScalar = 100
	if err := run(cfg, runOptions{show: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no private scalar") {
		t.Fatalf("expected recovery failure, got %v", err)
	}
}

func TestValidityCap(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.Leaf.ValidityHours = 24 * 30
	if err := run(cfg, runOptions{show: true}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected validity cap error")
	}
}

func TestCLISANsInLeaf(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	if err := applySANs(&cfg.Leaf, []string{"cli.example", "198.51.100.1", "URI:https://cli.example/"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(cfg, runOptions{show: true}, &out); err != nil {
		t.Fatal(err)
	}
	leaf := parsePEMCerts(t, out.Bytes())[0]
	got := strings.Join(subjectAltNames(leaf), ",")
	if got != "DNS:cli.example,IP:198.51.100.1,URI:https://cli.example/" || leaf.Subject.CommonName != "cli.example" {
		t.Errorf("SANs %q, CN %q", got, leaf.Subject.CommonName)
	}
}
