package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
)

// addChainRequest is the body of an RFC 6962 POST /ct/v1/add-chain request.
// []byte fields marshal as standard base64, i.e. base64-encoded DER.
type addChainRequest struct {
	Chain [][]byte `json:"chain"`
}

// chainCerts returns leaf, issuing CA and (if configured) root.
func chainCerts(res *issued) []*x509.Certificate {
	certs := []*x509.Certificate{res.leaf, res.ca}
	if res.root != nil {
		certs = append(certs, res.root)
	}
	return certs
}

// writeChain prints the complete chain as PEM.
func writeChain(w io.Writer, res *issued) {
	for _, c := range chainCerts(res) {
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
}

// writeAddChain prints the complete chain as an RFC 6962 add-chain request.
func writeAddChain(w io.Writer, res *issued) error {
	var req addChainRequest
	for _, c := range chainCerts(res) {
		req.Chain = append(req.Chain, c.Raw)
	}
	return json.NewEncoder(w).Encode(req)
}
