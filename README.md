# emudhra-poc

Proof of concept for the eMudhra emSign ECC G3 intermediate key compromise
([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)).
The CA private keys are tiny integers, so they can be recovered from the
public CA certificates and used to sign arbitrary leaf certificates.
All affected intermediates are revoked (caCompromise).

The tool recovers the CA key from the CA certificate, issues a leaf
certificate (OU `PoC`, max. 7 days validity) and verifies the result.

## Usage

```
go build -o emudhra-poc .
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

## References

- https://github.com/Fluepke/emudrahahahahaha
- https://github.com/galadran/we-have-a-problem.com
- https://emudhra.we-have-a-problem.com/
