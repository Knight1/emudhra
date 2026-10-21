package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, dir string, cfg *Config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLI(t *testing.T) {
	dir := t.TempDir()
	config := writeConfig(t, dir, testConfig(dir, writeWeakCA(t, dir, testScalar)))

	cases := []struct {
		name       string
		args       []string
		code       int
		wantStdout string
		wantStderr string
	}{
		{"show with san", []string{"-config", config, "-show", "-san", "cli.example"}, 0, "-----BEGIN CERTIFICATE-----", ""},
		{"bad san", []string{"-config", config, "-san", "bogus:x"}, 1, "", "unknown SAN type"},
		{"missing config", []string{"-config", filepath.Join(dir, "missing.json")}, 1, "", "error:"},
		{"run error", []string{"-config", config, "-san", "IP:nope"}, 1, "", "invalid ip address"},
		{"unknown flag", []string{"-nope"}, 2, "", "flag provided but not defined"},
		{"help", []string{"-h"}, 0, "", "Usage of emudhra-poc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli(tc.args, &stdout, &stderr); code != tc.code {
				t.Errorf("exit code %d, want %d (stderr: %s)", code, tc.code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Errorf("stdout missing %q:\n%s", tc.wantStdout, stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr missing %q:\n%s", tc.wantStderr, stderr.String())
			}
		})
	}

	var stdout bytes.Buffer
	cli([]string{"-config", config, "-show", "-san", "cli.example"}, &stdout, &bytes.Buffer{})
	if sans := subjectAltNames(parsePEMCerts(t, stdout.Bytes())[0]); len(sans) != 1 || sans[0] != "DNS:cli.example" {
		t.Errorf("-san not applied: %v", sans)
	}
}

func TestMainExitCode(t *testing.T) {
	stderr, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()

	oldArgs, oldStderr, oldExit := os.Args, os.Stderr, exit
	defer func() { os.Args, os.Stderr, exit = oldArgs, oldStderr, oldExit }()

	code := -1
	os.Args = []string{"emudhra-poc", "-config", filepath.Join(t.TempDir(), "missing.json")}
	os.Stderr = stderr
	exit = func(c int) { code = c }
	main()

	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
}
