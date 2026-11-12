package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// Certificate Transparency (RFC 6962): the leaf is first issued as a
// precertificate, which is submitted to every configured log; the returned
// SCTs are embedded in the final certificate.

var (
	oidCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidSCTList  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// sctResponse is the body of an add-pre-chain response. []byte fields are
// base64 in JSON; Signature is the TLS-encoded DigitallySigned struct.
type sctResponse struct {
	SCTVersion uint8  `json:"sct_version"`
	ID         []byte `json:"id"`
	Timestamp  uint64 `json:"timestamp"`
	Extensions []byte `json:"extensions"`
	Signature  []byte `json:"signature"`
}

// sctResult is the outcome of submitting the precertificate to one log.
type sctResult struct {
	log CTLog
	sct *sctResponse
	err error
}

// addSCTs issues a precertificate for tmpl, submits it to every log and adds
// the SCT list extension to tmpl. Logs that reject the precertificate are
// recorded in the results; at least one SCT is required.
func addSCTs(tmpl *x509.Certificate, logs []CTLog, ca, root *x509.Certificate, leafPub crypto.PublicKey, caKey crypto.Signer) ([]sctResult, error) {
	pre := *tmpl
	pre.ExtraExtensions = append(slices.Clone(tmpl.ExtraExtensions),
		pkix.Extension{Id: oidCTPoison, Critical: true, Value: asn1.NullBytes})
	der, err := x509.CreateCertificate(rand.Reader, &pre, ca, leafPub, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign precertificate: %w", err)
	}
	chain := [][]byte{der, ca.Raw}
	if root != nil {
		chain = append(chain, root.Raw)
	}

	var results []sctResult
	var list []byte
	var failed []string
	for _, l := range logs {
		sct, err := submitPrecert(httpClient, l.URL, chain)
		results = append(results, sctResult{log: l, sct: sct, err: err})
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", l.URL, err))
			continue
		}
		s := serializeSCT(sct)
		list = binary.BigEndian.AppendUint16(list, uint16(len(s)))
		list = append(list, s...)
	}
	if len(list) == 0 {
		return results, fmt.Errorf("no CT log returned an SCT: %s", strings.Join(failed, "; "))
	}

	// Marshalling a byte slice as an OCTET STRING cannot fail.
	value, _ := asn1.Marshal(append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...))
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidSCTList, Value: value})
	return results, nil
}

// submitPrecert posts chain (precertificate first) to the log's
// add-pre-chain endpoint and returns the SCT.
func submitPrecert(client *http.Client, logURL string, chain [][]byte) (*sctResponse, error) {
	// Marshalling [][]byte cannot fail.
	body, _ := json.Marshal(addChainRequest{Chain: chain})
	resp, err := client.Post(strings.TrimSuffix(logURL, "/")+"/ct/v1/add-pre-chain", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var sct sctResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDownload)).Decode(&sct); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if sct.SCTVersion != 0 || len(sct.ID) != sha256.Size {
		return nil, fmt.Errorf("unsupported SCT (version %d, log ID of %d bytes)", sct.SCTVersion, len(sct.ID))
	}
	return &sct, nil
}

// serializeSCT returns the TLS encoding of a v1 SCT (RFC 6962, 3.2).
func serializeSCT(s *sctResponse) []byte {
	b := append([]byte{s.SCTVersion}, s.ID...)
	b = binary.BigEndian.AppendUint64(b, s.Timestamp)
	b = binary.BigEndian.AppendUint16(b, uint16(len(s.Extensions)))
	b = append(b, s.Extensions...)
	return append(b, s.Signature...)
}

// sctSignedData returns the data a log signs for a precertificate entry:
// tbs is the TBSCertificate without the poison and SCT list extensions.
func sctSignedData(s *sctResponse, issuerSPKI, tbs []byte) []byte {
	issuerKeyHash := sha256.Sum256(issuerSPKI)
	b := []byte{s.SCTVersion, 0} // signature_type certificate_timestamp
	b = binary.BigEndian.AppendUint64(b, s.Timestamp)
	b = binary.BigEndian.AppendUint16(b, 1) // entry_type precert_entry
	b = append(b, issuerKeyHash[:]...)
	b = append(b, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
	b = append(b, tbs...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(s.Extensions)))
	return append(b, s.Extensions...)
}

// verifySCT checks an embedded SCT against the final certificate leaf, using
// the log's base64 DER public key.
func verifySCT(s *sctResponse, key string, leaf, ca *x509.Certificate) error {
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("log key: %w", err)
	}
	if id := sha256.Sum256(der); !bytes.Equal(id[:], s.ID) {
		return errors.New("log ID does not match the log key")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("log key: %w", err)
	}
	tbs, err := removeExtension(leaf.RawTBSCertificate, oidSCTList)
	if err != nil {
		return fmt.Errorf("leaf TBSCertificate: %w", err)
	}
	return verifyDigitallySigned(pub, sctSignedData(s, ca.RawSubjectPublicKeyInfo, tbs), s.Signature)
}

// verifyDigitallySigned checks a TLS DigitallySigned struct with SHA-256.
func verifyDigitallySigned(pub crypto.PublicKey, data, ds []byte) error {
	if len(ds) < 4 || ds[0] != 4 || int(binary.BigEndian.Uint16(ds[2:])) != len(ds)-4 {
		return errors.New("malformed SCT signature")
	}
	h := sha256.Sum256(data)
	sig := ds[4:]
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		if ds[1] == 3 && ecdsa.VerifyASN1(pub, h[:], sig) {
			return nil
		}
	case *rsa.PublicKey:
		if ds[1] == 1 && rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil {
			return nil
		}
	default:
		return fmt.Errorf("unsupported log key type %T", pub)
	}
	return errors.New("invalid SCT signature")
}

// removeExtension returns tbs without the extension oid. Everything else
// keeps its original encoding.
func removeExtension(tbs []byte, oid asn1.ObjectIdentifier) ([]byte, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &seq); err != nil {
		return nil, err
	}
	var fields []byte
	for rest := seq.Bytes; len(rest) > 0; {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return nil, err
		}
		if f.Class == asn1.ClassContextSpecific && f.Tag == 3 {
			if f.FullBytes, err = removeFromExtensions(f.Bytes, oid); err != nil {
				return nil, err
			}
		}
		fields = append(fields, f.FullBytes...)
	}
	return asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: fields})
}

// removeFromExtensions returns the [3] EXPLICIT extensions field without
// the extension oid. The leaf always keeps other extensions (key usage,
// basic constraints), so the result is never empty.
func removeFromExtensions(explicit []byte, oid asn1.ObjectIdentifier) ([]byte, error) {
	var raws []asn1.RawValue
	if _, err := asn1.Unmarshal(explicit, &raws); err != nil {
		return nil, err
	}
	var kept []byte
	for _, r := range raws {
		var ext pkix.Extension
		if _, err := asn1.Unmarshal(r.FullBytes, &ext); err != nil {
			return nil, err
		}
		if !ext.Id.Equal(oid) {
			kept = append(kept, r.FullBytes...)
		}
	}
	// Marshalling a RawValue cannot fail.
	seq, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: seq})
}

// reportSCTs prints the CT results of the leaf; signatures are checked for
// logs with a configured key.
func reportSCTs(w io.Writer, res *issued, report func(string, error)) {
	if len(res.scts) == 0 {
		return
	}
	n := 0
	for _, r := range res.scts {
		switch {
		case r.err != nil:
			fmt.Fprintf(w, "  [INFO] %s rejected the precertificate: %v\n", r.log.URL, r.err)
			continue
		case r.log.Key == "":
			fmt.Fprintf(w, "  [INFO] SCT from %s embedded (no log key configured, signature not checked)\n", r.log.URL)
		default:
			report("SCT from "+r.log.URL+" verifies against the leaf", verifySCT(r.sct, r.log.Key, res.leaf, res.ca))
		}
		n++
	}
	if n < 2 {
		fmt.Fprintf(w, "  [INFO] %d SCT embedded; Chrome and Apple require at least 2 from distinct log operators\n", n)
	}
}
