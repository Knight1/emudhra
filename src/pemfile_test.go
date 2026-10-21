package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCertErrors(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing":    filepath.Join(dir, "missing.pem"),
		"not pem":    junk,
		"wrong type": writePEM(t, filepath.Join(dir, "key.pem"), "PRIVATE KEY", nil),
	} {
		if _, err := readCert(path); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestReadECKey(t *testing.T) {
	dir := t.TempDir()
	want := scalarKey(t, testScalar)
	for name, path := range map[string]string{
		"sec1":  writeECKey(t, filepath.Join(dir, "sec1.key"), want),
		"pkcs8": writePKCS8Key(t, filepath.Join(dir, "pkcs8.key"), want),
	} {
		got, err := readECKey(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !got.Equal(want) {
			t.Errorf("%s: key mismatch", name)
		}
	}
}

func TestReadECKeyErrors(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(junk, []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing":       filepath.Join(dir, "missing.key"),
		"not pem":       junk,
		"bad pkcs8":     writePEM(t, filepath.Join(dir, "bad.key"), "PRIVATE KEY", []byte{1, 2, 3}),
		"rsa pkcs8":     writePKCS8Key(t, filepath.Join(dir, "rsa.key"), testRSAKey()),
		"unknown block": writePEM(t, filepath.Join(dir, "cert.key"), "CERTIFICATE", nil),
	} {
		if _, err := readECKey(path); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
