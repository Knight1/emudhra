package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplySANs(t *testing.T) {
	lc := LeafConfig{DNSNames: []string{"from-config.example"}}
	err := applySANs(&lc, []string{"a.example", "DNS:b.example", "192.0.2.7", "2001:db8::1", "IP:::1",
		"ops@a.example", "https://a.example/x", "URI:spiffe://a/b"})
	if err != nil {
		t.Fatal(err)
	}
	want := LeafConfig{
		DNSNames:       []string{"a.example", "b.example"},
		IPAddresses:    []string{"192.0.2.7", "2001:db8::1", "::1"},
		EmailAddresses: []string{"ops@a.example"},
		URIs:           []string{"https://a.example/x", "spiffe://a/b"},
	}
	if fmt.Sprint(lc) != fmt.Sprint(want) {
		t.Errorf("got  %+v\nwant %+v", lc, want)
	}
	if err := applySANs(&lc, []string{"bogus:x"}); err == nil {
		t.Error("expected error for unknown SAN type")
	}
}

func TestSANFlagSplitsCommas(t *testing.T) {
	var s sanFlag
	s.Set("a.example, IP:192.0.2.1")
	s.Set("b.example")
	if got := s.String(); got != "a.example,IP:192.0.2.1,b.example" {
		t.Errorf("got %q", got)
	}
}

func TestApplySANsEmailPrefix(t *testing.T) {
	var lc LeafConfig
	if err := applySANs(&lc, []string{"email:ops@a.example"}); err != nil {
		t.Fatal(err)
	}
	if len(lc.EmailAddresses) != 1 || lc.EmailAddresses[0] != "ops@a.example" {
		t.Errorf("got %+v", lc)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "root.pem")
	path := filepath.Join(dir, "config.json")
	data := `{"ca_cert": "keys/ca.pem", "root_cert": "` + abs + `",
		"leaf": {"common_name": "a"}, "output": {"cert": "out/c.pem", "key": "out/k.pem"}}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		cfg.CACert:       filepath.Join(dir, "keys", "ca.pem"),
		cfg.RootCert:     abs,
		cfg.Output.Cert:  filepath.Join(dir, "out", "c.pem"),
		cfg.Output.Key:   filepath.Join(dir, "out", "k.pem"),
		cfg.CAKey:        "",
		cfg.Output.Chain: "",
	}
	for got, w := range want {
		if got != w {
			t.Errorf("path %q, want %q", got, w)
		}
	}
}

func TestLoadConfigErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected error for missing file")
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"bogus": 1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error for unknown field, got %v", err)
	}
}
