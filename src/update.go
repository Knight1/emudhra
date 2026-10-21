package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// maxDownload bounds every download; OneCRL is below 1 MiB.
const maxDownload = 64 << 20

// oneCRLURL is Mozilla's OneCRL in Firefox Remote Settings. It and
// httpClient are replaced in tests.
var (
	oneCRLURL  = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records"
	httpClient = &http.Client{Timeout: time.Minute}
)

// updateRevocation downloads the CRLs referenced by the certificates in
// keysDir and Mozilla's OneCRL into dir. Each CRL must be signed by a
// certificate in rootsDir; OneCRL is reduced to the records concerning the
// certificates in keysDir and sorted, so the cache only changes when the
// data does.
func updateRevocation(w io.Writer, client *http.Client, keysDir, rootsDir, dir, oneCRLSource string) error {
	certs, err := readCertDir(keysDir)
	if err != nil {
		return err
	}
	roots, err := readCertDir(rootsDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var urls []string
	for _, c := range certs {
		urls = append(urls, c.CRLDistributionPoints...)
	}
	slices.Sort(urls)
	for _, url := range slices.Compact(urls) {
		der, err := fetch(client, url)
		if err != nil {
			return err
		}
		crl, err := verifyCRL(der, roots)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		path := filepath.Join(dir, crlCacheName(url))
		if err := os.WriteFile(path, der, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(w, "CRL %s -> %s (%d entries, next update %s)\n",
			url, path, len(crl.RevokedCertificateEntries), crl.NextUpdate.UTC().Format(time.RFC3339))
	}

	data, err := fetch(client, oneCRLSource)
	if err != nil {
		return err
	}
	var list oneCRL
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("OneCRL: %w", err)
	}
	kept := oneCRL{Data: []oneCRLRecord{}}
	for _, r := range list.Data {
		if r.concerns(certs) {
			kept.Data = append(kept.Data, r)
		}
	}
	slices.SortFunc(kept.Data, func(a, b oneCRLRecord) int { return strings.Compare(a.ID, b.ID) })
	// Marshalling plain strings cannot fail.
	out, _ := json.MarshalIndent(kept, "", "  ")
	path := filepath.Join(dir, oneCRLFile)
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "OneCRL -> %s (%d of %d records)\n", path, len(kept.Data), len(list.Data))
	return nil
}

func fetch(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

// readCertDir reads all *.pem certificates in dir.
func readCertDir(dir string) ([]*x509.Certificate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		c, err := readCert(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}
