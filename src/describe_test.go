package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"testing"
)

func TestKeyDescriptionUnknownType(t *testing.T) {
	if got := keyDescription(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))); got != "ed25519.PublicKey" {
		t.Errorf("got %q", got)
	}
}

func TestExtKeyUsageNameUnknown(t *testing.T) {
	u := x509.ExtKeyUsageOCSPSigning
	if got, want := extKeyUsageName(u), fmt.Sprintf("EKU(%d)", u); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
