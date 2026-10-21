package main

import (
	"fmt"
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
