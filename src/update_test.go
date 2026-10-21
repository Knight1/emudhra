package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateRevocationErrors(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *revFixture) (oneCRLSource string)
		want  string
	}{
		{"missing keys dir", func(t *testing.T, f *revFixture) string {
			f.keysDir = filepath.Join(f.keysDir, "missing")
			return ""
		}, "no such file"},
		{"bad cert in keys dir", func(t *testing.T, f *revFixture) string {
			writePEM(t, filepath.Join(f.keysDir, "bad.pem"), "PRIVATE KEY", nil)
			return ""
		}, "bad.pem"},
		{"missing roots dir", func(t *testing.T, f *revFixture) string {
			f.rootsDir = filepath.Join(f.rootsDir, "missing")
			return ""
		}, "no such file"},
		{"cache dir not creatable", func(t *testing.T, f *revFixture) string {
			f.revDir = filepath.Join(f.keysDir, "README", "revocation")
			return ""
		}, "not a directory"},
		{"crl download fails", func(t *testing.T, f *revFixture) string {
			f.server.Close()
			return ""
		}, "connection refused"},
		{"crl not found", func(t *testing.T, f *revFixture) string {
			f.crl = nil
			f.server.Config.Handler = http.NotFoundHandler()
			return ""
		}, "404"},
		{"crl untrusted", func(t *testing.T, f *revFixture) string {
			os.Remove(filepath.Join(f.rootsDir, "root.pem"))
			return ""
		}, "not signed by any trusted root"},
		{"crl not writable", func(t *testing.T, f *revFixture) string {
			name := filepath.Join(f.revDir, crlCacheName(f.ca.CRLDistributionPoints[0]))
			if err := os.MkdirAll(name, 0o755); err != nil {
				t.Fatal(err)
			}
			return f.server.URL + "/onecrl"
		}, "is a directory"},
		{"onecrl not found", func(t *testing.T, f *revFixture) string {
			return f.server.URL + "/missing"
		}, "404"},
		{"onecrl invalid", func(t *testing.T, f *revFixture) string {
			f.onecrl = []byte("{")
			return f.server.URL + "/onecrl"
		}, "OneCRL:"},
		{"onecrl not writable", func(t *testing.T, f *revFixture) string {
			if err := os.MkdirAll(filepath.Join(f.revDir, oneCRLFile), 0o755); err != nil {
				t.Fatal(err)
			}
			return f.server.URL + "/onecrl"
		}, "is a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRevFixture(t, true)
			source := tc.setup(t, f)
			client := &http.Client{Timeout: 5 * time.Second}
			err := updateRevocation(&bytes.Buffer{}, client, f.keysDir, f.rootsDir, f.revDir, source)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestRunRevocation(t *testing.T) {
	f := newRevFixture(t, true)
	if err := f.update(t); err != nil {
		t.Fatal(err)
	}
	caKeyDir := t.TempDir()
	cfg := testConfig(caKeyDir, filepath.Join(f.keysDir, "ca.pem"))
	opts := runOptions{revocation: true, rootsDir: f.rootsDir, revocationDir: f.revDir}

	var out bytes.Buffer
	if err := run(cfg, opts, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	revocation := strings.Index(out.String(), "Revocation (cache:")
	output := strings.Index(out.String(), "\nOutput\n")
	if revocation < 0 || output < revocation || !strings.Contains(out.String(), "REVOKED at") {
		t.Errorf("expected revocation section before output:\n%s", out.String())
	}

	opts.rootsDir = filepath.Join(f.rootsDir, "missing")
	out.Reset()
	err := run(cfg, opts, &out)
	if err == nil || !strings.HasPrefix(err.Error(), "revocation:") {
		t.Fatalf("expected revocation error, got %v", err)
	}
	if !strings.Contains(out.String(), "\nOutput\n") {
		t.Errorf("output section missing after failed revocation check:\n%s", out.String())
	}
}

func TestCLIRevocation(t *testing.T) {
	f := newRevFixture(t, true)
	oldURL, oldClient := oneCRLURL, httpClient
	defer func() { oneCRLURL, httpClient = oldURL, oldClient }()
	oneCRLURL, httpClient = f.server.URL+"/onecrl", f.server.Client()

	var stdout, stderr bytes.Buffer
	args := []string{"-update-revocation", "-keys", f.keysDir, "-roots", f.rootsDir, "-revocation-dir", f.revDir}
	if code := cli(args, &stdout, &stderr); code != 0 {
		t.Fatalf("update exit code %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OneCRL ->") {
		t.Errorf("unexpected update output:\n%s", stdout.String())
	}

	dir := t.TempDir()
	config := writeConfig(t, dir, testConfig(dir, filepath.Join(f.keysDir, "ca.pem")))
	stdout.Reset()
	args = []string{"-config", config, "-revocation", "-roots", f.rootsDir, "-revocation-dir", f.revDir}
	if code := cli(args, &stdout, &stderr); code != 0 {
		t.Fatalf("revocation exit code %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OneCRL: LISTED") {
		t.Errorf("unexpected output:\n%s", stdout.String())
	}
}
