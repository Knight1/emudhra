package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// revFixture is a root, a weak CA it issued and a test server that serves
// the root's CRL at /root.crl and OneCRL at /onecrl.
type revFixture struct {
	keysDir, rootsDir, revDir string
	root, ca                  *x509.Certificate
	rootKey                   *ecdsa.PrivateKey
	crl, onecrl               []byte
	server                    *httptest.Server
}

func newRevFixture(t *testing.T, revoked bool) *revFixture {
	t.Helper()
	dir := t.TempDir()
	f := &revFixture{
		keysDir:  filepath.Join(dir, "keys"),
		rootsDir: filepath.Join(dir, "roots"),
		revDir:   filepath.Join(dir, "revocation"),
	}
	for _, d := range []string{f.keysDir, f.rootsDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/root.crl":
			w.Write(f.crl)
		case "/onecrl":
			w.Write(f.onecrl)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)

	var err error
	if f.rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	rootTmpl := caTemplate("Test Root")
	f.root = newTestCert(t, rootTmpl, rootTmpl, &f.rootKey.PublicKey, f.rootKey)
	caKey := scalarKey(t, testScalar)
	caTmpl := caTemplate("Weak Test CA")
	caTmpl.SerialNumber = big.NewInt(0xa0) // high bit set: DER adds a leading zero
	caTmpl.CRLDistributionPoints = []string{f.server.URL + "/root.crl"}
	f.ca = newTestCert(t, caTmpl, f.root, &caKey.PublicKey, f.rootKey)
	writePEM(t, filepath.Join(f.rootsDir, "root.pem"), "CERTIFICATE", f.root.Raw)
	writePEM(t, filepath.Join(f.keysDir, "ca.pem"), "CERTIFICATE", f.ca.Raw)
	if err := os.WriteFile(filepath.Join(f.keysDir, "README"), []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := []x509.RevocationListEntry{{SerialNumber: big.NewInt(1), RevocationTime: time.Now()}}
	if revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber: f.ca.SerialNumber, RevocationTime: time.Now(), ReasonCode: 2,
		})
	}
	f.crl = f.makeCRL(t, f.root, f.rootKey, entries, time.Now().Add(24*time.Hour))

	spki := sha256.Sum256(f.ca.RawSubjectPublicKeyInfo)
	b := base64.StdEncoding.EncodeToString
	records := []oneCRLRecord{
		{ID: "z-unrelated", IssuerName: b([]byte("someone else")), SerialNumber: b([]byte{1})},
		{ID: "b-other-serial", IssuerName: b(f.ca.RawIssuer), SerialNumber: b([]byte{1})},
	}
	if revoked {
		records = append(records,
			oneCRLRecord{ID: "c-serial", IssuerName: b(f.ca.RawIssuer), SerialNumber: b([]byte{0, 0xa0})},
			oneCRLRecord{ID: "a-spki", Subject: b(f.ca.RawSubject), PubKeyHash: b(spki[:])})
		records[2].Details.Bug = "https://bugzilla.mozilla.org/show_bug.cgi?id=1"
	}
	f.onecrl = mustJSON(t, oneCRL{Data: records})
	return f
}

func (f *revFixture) makeCRL(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, entries []x509.RevocationListEntry, next time.Time) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                next,
		RevokedCertificateEntries: entries,
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *revFixture) update(t *testing.T) error {
	t.Helper()
	return updateRevocation(&bytes.Buffer{}, f.server.Client(), f.keysDir, f.rootsDir, f.revDir, f.server.URL+"/onecrl")
}

func TestUpdateAndCheckRevocation(t *testing.T) {
	f := newRevFixture(t, true)
	var out bytes.Buffer
	if err := updateRevocation(&out, f.server.Client(), f.keysDir, f.rootsDir, f.revDir, f.server.URL+"/onecrl"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(3 of 4 records)") {
		t.Errorf("unexpected update output:\n%s", out.String())
	}

	var cached oneCRL
	data, err := os.ReadFile(filepath.Join(f.revDir, oneCRLFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cached); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range cached.Data {
		ids = append(ids, r.ID)
	}
	if got := strings.Join(ids, ","); got != "a-spki,b-other-serial,c-serial" {
		t.Errorf("cached OneCRL records %s, want filtered and sorted", got)
	}

	out.Reset()
	if err := checkRevocation(&out, f.ca, []*x509.Certificate{f.root}, f.revDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"REVOKED at", "reason cACompromise", "OneCRL: LISTED (https://bugzilla.mozilla.org/show_bug.cgi?id=1)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "STALE") {
		t.Errorf("fresh CRL reported as stale:\n%s", out.String())
	}
}

func TestCheckRevocationNotRevoked(t *testing.T) {
	f := newRevFixture(t, false)
	if err := f.update(t); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := checkRevocation(&out, f.ca, []*x509.Certificate{f.root}, f.revDir, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"STALE): not revoked", "OneCRL: not listed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestCheckRevocationNoDistributionPoint(t *testing.T) {
	f := newRevFixture(t, false)
	if err := f.update(t); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := checkRevocation(&out, f.root, []*x509.Certificate{f.root}, f.revDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no CRL distribution point") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
}

func TestCheckRevocationErrors(t *testing.T) {
	f := newRevFixture(t, true)
	if err := f.update(t); err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(f.revDir, crlCacheName(f.ca.CRLDistributionPoints[0]))
	oneCRLPath := filepath.Join(f.revDir, oneCRLFile)

	// A CA from another issuer that points at the same (validly signed) CRL.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot := newTestCert(t, caTemplate("Other Root"), caTemplate("Other Root"), &otherKey.PublicKey, otherKey)
	tmpl := caTemplate("Foreign CA")
	tmpl.CRLDistributionPoints = f.ca.CRLDistributionPoints
	foreign := newTestCert(t, tmpl, otherRoot, &otherKey.PublicKey, otherKey)

	cases := []struct {
		name  string
		ca    *x509.Certificate
		roots []*x509.Certificate
		setup func()
		want  string
	}{
		{"untrusted crl", f.ca, nil, func() {}, "not signed by any trusted root"},
		{"foreign issuer", foreign, []*x509.Certificate{f.root}, func() {}, "not by the CA's issuer"},
		{"bad onecrl", f.ca, []*x509.Certificate{f.root}, func() { os.WriteFile(oneCRLPath, []byte("{"), 0o644) }, "OneCRL:"},
		{"missing onecrl", f.ca, []*x509.Certificate{f.root}, func() { os.Remove(oneCRLPath) }, "OneCRL not cached"},
		{"missing crl", f.ca, []*x509.Certificate{f.root}, func() { os.Remove(crlPath) }, "not cached"},
	}
	for _, tc := range cases {
		tc.setup()
		err := checkRevocation(&bytes.Buffer{}, tc.ca, tc.roots, f.revDir, time.Now())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want error containing %q", tc.name, err, tc.want)
		}
	}
}

func TestVerifyCRLParseError(t *testing.T) {
	if _, err := verifyCRL([]byte("junk"), nil); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCRLCacheName(t *testing.T) {
	for url, want := range map[string]string{
		"http://crl.emsign.com/?roottlscag3.crl":              "crl.emsign.com_roottlscag3.crl",
		"https://crl.comodoca.com/AAACertificateServices.crl": "crl.comodoca.com_AAACertificateServices.crl",
		"http://127.0.0.1:8080/crl?id=7":                      "127.0.0.1_8080_crl_id_7.crl",
	} {
		if got := crlCacheName(url); got != want {
			t.Errorf("%s: got %s, want %s", url, got, want)
		}
	}
}

func TestReasonName(t *testing.T) {
	if got := reasonName(2); got != "cACompromise" {
		t.Errorf("got %q", got)
	}
	if got := reasonName(7); got != "reason 7" {
		t.Errorf("got %q", got)
	}
}

func TestOneCRLRecordMatches(t *testing.T) {
	c := &x509.Certificate{
		RawIssuer:               []byte("issuer"),
		RawSubject:              []byte("subject"),
		RawSubjectPublicKeyInfo: []byte("spki"),
		SerialNumber:            big.NewInt(5),
		Subject:                 pkix.Name{CommonName: "c"},
	}
	b := base64.StdEncoding.EncodeToString
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	for _, tc := range []struct {
		name string
		r    oneCRLRecord
		want bool
	}{
		{"issuer and serial", oneCRLRecord{IssuerName: b(c.RawIssuer), SerialNumber: b([]byte{0, 5})}, true},
		{"wrong serial", oneCRLRecord{IssuerName: b(c.RawIssuer), SerialNumber: b([]byte{6})}, false},
		{"invalid base64", oneCRLRecord{IssuerName: "!!", SerialNumber: b([]byte{5})}, false},
		{"subject and key", oneCRLRecord{Subject: b(c.RawSubject), PubKeyHash: b(spki[:])}, true},
		{"wrong key", oneCRLRecord{Subject: b(c.RawSubject), PubKeyHash: b([]byte("x"))}, false},
	} {
		if got := tc.r.matches(c); got != tc.want {
			t.Errorf("%s: got %t, want %t", tc.name, got, tc.want)
		}
	}
}
