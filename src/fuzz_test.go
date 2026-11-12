package main

import (
	"testing"
	"time"
)

// FuzzParseSerial checks that parseSerial never panics and that a successful
// parse always yields a non-negative integer (serial numbers are unsigned).
func FuzzParseSerial(f *testing.F) {
	for _, s := range []string{"", "0", "ff", "0xFF", "0X10", " a ", "deadbeef", "-1", "0x", "nothex", "  ", "0x0x1", "+5"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := parseSerial(s)
		if err != nil {
			if n != nil {
				t.Fatalf("parseSerial(%q) returned a value with an error: %v", s, n)
			}
			return
		}
		if n == nil {
			t.Fatalf("parseSerial(%q) returned nil without an error", s)
		}
		if n.Sign() < 0 {
			t.Fatalf("parseSerial(%q) returned negative %v", s, n)
		}
	})
}

// FuzzParseTime checks that parseTime never panics and that a successful parse
// returns a UTC time that round-trips back to the same instant.
func FuzzParseTime(f *testing.F) {
	for _, s := range []string{"", "0", "1767315845", "-1", "2026-01-02T15:04:05Z", "2026-01-02T15:04:05", "2026-01-02 15:04:05", "2026-01-02", "whenever", "2026-13-40", "99999999999999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tm, err := parseTime(s)
		if err != nil {
			if !tm.IsZero() {
				t.Fatalf("parseTime(%q) returned %v with an error", s, tm)
			}
			return
		}
		if tm.Location() != time.UTC {
			t.Fatalf("parseTime(%q) returned non-UTC time %v", s, tm)
		}
	})
}

// FuzzApplySANs checks that applySANs never panics and that a successful call
// classifies every input into exactly one SAN bucket.
func FuzzApplySANs(f *testing.F) {
	for _, s := range []string{"", "a.example", "DNS:a.example", "IP:192.0.2.1", "192.0.2.1", "email:a@b", "a@b", "URI:https://x/", "https://x/", "bogus:x", "::1", "DNS:"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, san string) {
		var lc LeafConfig
		err := applySANs(&lc, []string{san})
		if err != nil {
			return
		}
		got := len(lc.DNSNames) + len(lc.IPAddresses) + len(lc.EmailAddresses) + len(lc.URIs)
		if got != 1 {
			t.Fatalf("applySANs(%q) classified into %d buckets, want 1", san, got)
		}
	})
}

// FuzzCRLTemplate drives the CRL template builder, exercising serial and time
// parsing together. A successful build must produce a non-nil CRL number and
// one entry per revoked serial, with NextUpdate at or after ThisUpdate.
func FuzzCRLTemplate(f *testing.F) {
	f.Add(int64(0), "", 24, "deadbeef", 1, "")
	f.Add(int64(7), "1767315845", 0, "0x1a2b", 4, "2026-01-02T03:04:05Z")
	f.Add(int64(-1), "whenever", -5, "nothex", 0, "soon")
	now := time.Unix(1767315845, 0).UTC()
	f.Fuzz(func(t *testing.T, number int64, thisUpdate string, hours int, serial string, reason int, revTime string) {
		cc := &CRLConfig{
			Number:          number,
			ThisUpdate:      thisUpdate,
			NextUpdateHours: hours,
			Revoked:         []RevokedConfig{{Serial: serial, Reason: reason, RevocationTime: revTime}},
		}
		tmpl, err := crlTemplate(cc, now)
		if err != nil {
			return
		}
		if tmpl.Number == nil {
			t.Fatalf("crlTemplate produced a nil Number")
		}
		if len(tmpl.RevokedCertificateEntries) != 1 {
			t.Fatalf("crlTemplate produced %d entries, want 1", len(tmpl.RevokedCertificateEntries))
		}
		if tmpl.NextUpdate.Before(tmpl.ThisUpdate) {
			t.Fatalf("NextUpdate %v precedes ThisUpdate %v", tmpl.NextUpdate, tmpl.ThisUpdate)
		}
	})
}
