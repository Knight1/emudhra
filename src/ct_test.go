package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLog is an httptest CT log. Under /ok it signs every precertificate
// with key; /reject, /badjson and /badversion fail in different ways.
type fakeLog struct {
	server *httptest.Server
	key    *ecdsa.PrivateKey
	keyB64 string

	mu     sync.Mutex
	chains [][][]byte // submitted chains
}

func newFakeLog(t *testing.T) *fakeLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeLog{key: key, keyB64: base64.StdEncoding.EncodeToString(der)}
	logID := sha256.Sum256(der)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /ok/ct/v1/add-pre-chain", func(w http.ResponseWriter, r *http.Request) {
		var req addChainRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.chains = append(f.chains, req.Chain)
		f.mu.Unlock()
		pre, err := x509.ParseCertificate(req.Chain[0])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		issuer, err := x509.ParseCertificate(req.Chain[1])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tbs, err := removeExtension(pre.RawTBSCertificate, oidCTPoison)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sct := &sctResponse{ID: logID[:], Timestamp: uint64(time.Now().UnixMilli())}
		sct.Signature = signDS(t, key, sctSignedData(sct, issuer.RawSubjectPublicKeyInfo, tbs))
		json.NewEncoder(w).Encode(sct)
	})
	mux.HandleFunc("POST /reject/ct/v1/add-pre-chain", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown root", http.StatusBadRequest)
	})
	mux.HandleFunc("POST /badjson/ct/v1/add-pre-chain", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{"))
	})
	mux.HandleFunc("POST /badversion/ct/v1/add-pre-chain", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&sctResponse{SCTVersion: 1, ID: logID[:]})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	oldClient := httpClient
	httpClient = f.server.Client()
	t.Cleanup(func() { httpClient = oldClient })
	return f
}

func (f *fakeLog) url(path string) string { return f.server.URL + path }

// signDS returns a TLS DigitallySigned struct (SHA-256, ECDSA) over data.
func signDS(t *testing.T, key *ecdsa.PrivateKey, data []byte) []byte {
	h := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Error(err)
	}
	return append(binary.BigEndian.AppendUint16([]byte{4, 3}, uint16(len(sig))), sig...)
}

// embeddedSCTs returns the number of SCTs in c's SCT list extension.
func embeddedSCTs(t *testing.T, c *x509.Certificate) int {
	t.Helper()
	for _, e := range c.Extensions {
		if e.Id.Equal(oidCTPoison) {
			t.Error("final certificate contains the poison extension")
		}
		if !e.Id.Equal(oidSCTList) {
			continue
		}
		var list []byte
		if _, err := asn1.Unmarshal(e.Value, &list); err != nil {
			t.Fatal(err)
		}
		if int(binary.BigEndian.Uint16(list)) != len(list)-2 {
			t.Fatalf("SCT list length mismatch")
		}
		n := 0
		for rest := list[2:]; len(rest) > 0; n++ {
			rest = rest[2+int(binary.BigEndian.Uint16(rest)):]
		}
		return n
	}
	return 0
}

func TestCTEmbedsSCTs(t *testing.T) {
	f := newFakeLog(t)
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.CTLogs = []CTLog{
		{URL: f.url("/ok/"), Key: f.keyB64},
		{URL: f.url("/ok")},
		{URL: f.url("/reject")},
	}

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		"[ OK ] SCT from " + f.url("/ok/") + " verifies against the leaf",
		"[INFO] SCT from " + f.url("/ok") + " embedded (no log key configured",
		"[INFO] " + f.url("/reject") + " rejected the precertificate: 400 Bad Request: unknown root",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "require at least 2") {
		t.Errorf("policy note printed with 2 SCTs:\n%s", out.String())
	}

	leaf, err := readCert(cfg.Output.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if n := embeddedSCTs(t, leaf); n != 2 {
		t.Errorf("embedded SCTs = %d, want 2", n)
	}
	for _, chain := range f.chains {
		pre, err := x509.ParseCertificate(chain[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(chain) != 2 || len(pre.UnhandledCriticalExtensions) != 1 || !pre.UnhandledCriticalExtensions[0].Equal(oidCTPoison) {
			t.Errorf("submitted chain of %d, critical extensions %v", len(chain), pre.UnhandledCriticalExtensions)
		}
		if pre.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			t.Error("precertificate serial differs from the final certificate")
		}
	}
}

func TestCTSingleSCTWithRoot(t *testing.T) {
	f := newFakeLog(t)
	dir := t.TempDir()
	caPath, rootPath := writeRootedCA(t, dir)
	cfg := testConfig(dir, caPath)
	cfg.RootCert = rootPath
	cfg.CTLogs = []CTLog{{URL: f.url("/ok"), Key: f.keyB64}}

	var out bytes.Buffer
	if err := run(cfg, runOptions{}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "[INFO] 1 SCT embedded; Chrome and Apple require at least 2") {
		t.Errorf("policy note missing:\n%s", out.String())
	}
	if len(f.chains) != 1 || len(f.chains[0]) != 3 {
		t.Errorf("submitted chains %d, want one of 3 certificates", len(f.chains))
	}
}

func TestCTFailures(t *testing.T) {
	f := newFakeLog(t)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.CTLogs = []CTLog{{URL: f.url("/reject")}, {URL: f.url("/badjson")}, {URL: f.url("/badversion")}, {URL: closed.URL}}
	err := run(cfg, runOptions{show: true}, &bytes.Buffer{})
	for _, want := range []string{"no CT log returned an SCT", "unknown root", "decode response", "unsupported SCT (version 1", closed.URL + ": Post"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want %q", err, want)
		}
	}

	cfg.Leaf.EmailAddresses = []string{"\u00fc@a.example"} // not an IA5String
	if err := run(cfg, runOptions{show: true}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "sign precertificate") {
		t.Errorf("error = %v, want sign precertificate", err)
	}
}

func TestCTLogFlag(t *testing.T) {
	f := newFakeLog(t)
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.CTLogs = []CTLog{{URL: f.url("/reject")}}
	config := writeConfig(t, dir, cfg)

	var stdout, stderr bytes.Buffer
	if code := cli([]string{"-config", config, "-show", "-ct-log", f.url("/ok")}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	if n := embeddedSCTs(t, parsePEMCerts(t, stdout.Bytes())[0]); n != 1 {
		t.Errorf("embedded SCTs = %d, want 1", n)
	}
}

func TestVerifySCTErrors(t *testing.T) {
	f := newFakeLog(t)
	dir := t.TempDir()
	cfg := testConfig(dir, writeWeakCA(t, dir, testScalar))
	cfg.CTLogs = []CTLog{{URL: f.url("/ok")}}
	res, err := issue(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sct := res.scts[0].sct
	if err := verifySCT(sct, f.keyB64, res.leaf, res.ca); err != nil {
		t.Fatalf("valid SCT: %v", err)
	}

	garbage := []byte("not a key")
	garbageID := sha256.Sum256(garbage)
	badTBS := *res.leaf
	badTBS.RawTBSCertificate = []byte{0x30}
	otherTS := *sct
	otherTS.Timestamp++

	for _, tc := range []struct {
		name string
		sct  *sctResponse
		key  string
		leaf *x509.Certificate
		want string
	}{
		{"base64", sct, "!", res.leaf, "log key"},
		{"log id", sct, base64.StdEncoding.EncodeToString(garbage), res.leaf, "log ID does not match"},
		{"key der", &sctResponse{ID: garbageID[:]}, base64.StdEncoding.EncodeToString(garbage), res.leaf, "log key"},
		{"tbs", sct, f.keyB64, &badTBS, "leaf TBSCertificate"},
		{"signature", &otherTS, f.keyB64, res.leaf, "invalid SCT signature"},
	} {
		if err := verifySCT(tc.sct, tc.key, tc.leaf, res.ca); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestVerifyDigitallySigned(t *testing.T) {
	data := []byte("signed data")
	h := sha256.Sum256(data)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, testRSAKey(), crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	rsaDS := append(binary.BigEndian.AppendUint16([]byte{4, 1}, uint16(len(rsaSig))), rsaSig...)
	ecDS := signDS(t, ecKey, data)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyDigitallySigned(testRSAKey().Public(), data, rsaDS); err != nil {
		t.Errorf("RSA: %v", err)
	}
	if err := verifyDigitallySigned(&ecKey.PublicKey, data, ecDS); err != nil {
		t.Errorf("ECDSA: %v", err)
	}
	for _, tc := range []struct {
		name string
		pub  crypto.PublicKey
		ds   []byte
		want string
	}{
		{"short", &ecKey.PublicKey, []byte{4, 3}, "malformed"},
		{"hash", &ecKey.PublicKey, append([]byte{2}, ecDS[1:]...), "malformed"},
		{"length", &ecKey.PublicKey, ecDS[:len(ecDS)-1], "malformed"},
		{"ecdsa alg", &ecKey.PublicKey, append([]byte{4, 1}, ecDS[2:]...), "invalid SCT signature"},
		{"rsa wrong data", testRSAKey().Public(), append([]byte{4, 1}, ecDS[2:]...), "invalid SCT signature"},
		{"ed25519", edPub, ecDS, "unsupported log key type"},
	} {
		if err := verifyDigitallySigned(tc.pub, data, tc.ds); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestRemoveExtension(t *testing.T) {
	key := scalarKey(t, testScalar)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "poc.example"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(3600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	without := newTestCert(t, tmpl, tmpl, &key.PublicKey, key)
	tmpl.ExtraExtensions = []pkix.Extension{{Id: oidCTPoison, Critical: true, Value: asn1.NullBytes}}
	with := newTestCert(t, tmpl, tmpl, &key.PublicKey, key)

	got, err := removeExtension(with.RawTBSCertificate, oidCTPoison)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, without.RawTBSCertificate) {
		t.Error("TBSCertificate without the extension differs from one issued without it")
	}

	for name, tbs := range map[string][]byte{
		"truncated":         {0x30},
		"truncated field":   {0x30, 0x01, 0x02},
		"extensions":        {0x30, 0x04, 0xa3, 0x02, 0x05, 0x00},
		"extension element": {0x30, 0x06, 0xa3, 0x04, 0x30, 0x02, 0x05, 0x00},
	} {
		if _, err := removeExtension(tbs, oidCTPoison); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
