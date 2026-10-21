// Command emudhra-poc demonstrates the eMudhra emSign ECC G3 intermediate key
// compromise (Mozilla bug 2083449): the CA private keys are tiny scalars, so
// anyone can recover them from the public CA certificate and issue leaf
// certificates that chain to the (now revoked/distrusted) intermediates.
//
// Every issued certificate is marked as a proof of concept and limited to a
// short validity period.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// exit is replaced in tests.
var exit = os.Exit

func main() {
	exit(cli(os.Args[1:], os.Stdout, os.Stderr))
}

// cli parses args, runs the tool and returns the process exit code.
func cli(args []string, stdout, stderr io.Writer) int {
	var sans sanFlag
	fs := flag.NewFlagSet("emudhra-poc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "config.json", "path to JSON config")
	show := fs.Bool("show", false, "only generate and print the certificate PEM; write no files and skip checks")
	chain := fs.Bool("chain", false, "also print the complete chain (leaf, CA, root if configured) as PEM")
	jsonOut := fs.Bool("json", false, "print only the complete chain as a CT add-chain JSON request; checks still run silently")
	revocation := fs.Bool("revocation", false, "also check the issuing CA against the cached CRL and OneCRL (see -update-revocation)")
	update := fs.Bool("update-revocation", false, "download the CRLs of all certificates in -keys and Mozilla's OneCRL into -revocation-dir, then exit")
	keysDir := fs.String("keys", "keys", "directory with the CA certificates, for -update-revocation")
	rootsDir := fs.String("roots", "roots", "directory with the root certificates that sign the CRLs")
	revocationDir := fs.String("revocation-dir", "revocation", "directory of the revocation cache")
	fs.Var(&sans, "san", "subject alternative name, repeatable or comma-separated (e.g. -san a.example,IP:192.0.2.1); replaces SANs from the config")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *update {
		return exitCode(stderr, updateRevocation(stdout, httpClient, *keysDir, *rootsDir, *revocationDir, oneCRLURL))
	}

	cfg, err := loadConfig(*configPath)
	if err == nil && len(sans) > 0 {
		err = applySANs(&cfg.Leaf, sans)
	}
	if err == nil {
		err = run(cfg, runOptions{
			show: *show, chain: *chain, json: *jsonOut,
			revocation: *revocation, rootsDir: *rootsDir, revocationDir: *revocationDir,
		}, stdout)
	}
	return exitCode(stderr, err)
}

// exitCode prints err, if any, and returns the matching exit code.
func exitCode(stderr io.Writer, err error) int {
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}
