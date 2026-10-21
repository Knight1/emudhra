// Command emudhra-poc demonstrates the eMudhra emSign ECC G3 intermediate key
// compromise (Mozilla bug 2083449): the CA private keys are tiny scalars, so
// anyone can recover them from the public CA certificate and issue leaf
// certificates that chain to the (now revoked/distrusted) intermediates.
//
// Every issued certificate is marked as a proof of concept and limited to a
// short validity period.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var sans sanFlag
	configPath := flag.String("config", "config.json", "path to JSON config")
	show := flag.Bool("show", false, "only generate and print the certificate PEM; write no files and skip checks")
	chain := flag.Bool("chain", false, "also print the complete chain (leaf, CA, root if configured) as PEM")
	jsonOut := flag.Bool("json", false, "print only the complete chain as a CT add-chain JSON request; checks still run silently")
	flag.Var(&sans, "san", "subject alternative name, repeatable or comma-separated (e.g. -san a.example,IP:192.0.2.1); replaces SANs from the config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(sans) > 0 {
		if err := applySANs(&cfg.Leaf, sans); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	opts := runOptions{show: *show, chain: *chain, json: *jsonOut}
	if err := run(cfg, opts, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
