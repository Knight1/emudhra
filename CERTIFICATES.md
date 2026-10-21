# Affected certificates

The 16 certificates from
[Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
(comments 0 and 2). Each intermediate exists twice, issued by eMudhra and
cross-signed by Sectigo; both versions share the same compromised P-384 key,
so the key files are identical per pair. All 16 are revoked (caCompromise).

crt.sh links may currently return 502.

## Issued by emSign Root TLS CA - G3 / emSign Root CS CA - G3

| Certificate | Censys | crt.sh | Files |
|---|---|---|---|
| EM DV TLS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493) | [crt.sh](https://crt.sh/?sha256=42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493) | [cert](<keys/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL (emSign Root TLS CA - G3).pem>), [key](<keys/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL (emSign Root TLS CA - G3).key>) |
| EM OV TLS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b) | [crt.sh](https://crt.sh/?sha256=98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b) | [cert](<keys/CN=EM OV TLS CA - G3B,O=eMudhra BV,C=NL (emSign Root TLS CA - G3).pem>), [key](<keys/CN=EM OV TLS CA - G3B,O=eMudhra BV,C=NL (emSign Root TLS CA - G3).key>) |
| EM EV TLS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838) | [crt.sh](https://crt.sh/?sha256=e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838) | [cert](<keys/CN=EM EV TLS CA - G3B,O=eMudhra BV,C=NL (emSign Root TLS CA - G3).pem>), [key](<keys/CN=EM EV TLS CA - G3B,O=eMudhra BV,C=NL (emSign Root TLS CA - G3).key>) |
| EM DV TLS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19) | [crt.sh](https://crt.sh/?sha256=0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19) | [cert](<keys/CN=EM DV TLS CA - G3C,O=eMudhra Inc,C=US (emSign Root TLS CA - G3).pem>), [key](<keys/CN=EM DV TLS CA - G3C,O=eMudhra Inc,C=US (emSign Root TLS CA - G3).key>) |
| EM OV TLS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f) | [crt.sh](https://crt.sh/?sha256=cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f) | [cert](<keys/CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US (emSign Root TLS CA - G3).pem>), [key](<keys/CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US (emSign Root TLS CA - G3).key>) |
| EM EV TLS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3) | [crt.sh](https://crt.sh/?sha256=432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3) | [cert](<keys/CN=EM EV TLS CA - G3C,O=eMudhra Inc,C=US (emSign Root TLS CA - G3).pem>), [key](<keys/CN=EM EV TLS CA - G3C,O=eMudhra Inc,C=US (emSign Root TLS CA - G3).key>) |
| EM OV CS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4) | [crt.sh](https://crt.sh/?sha256=9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4) | [cert](<keys/CN=EM OV CS CA - G3B,O=eMudhra BV,C=NL (emSign Root CS CA - G3).pem>), [key](<keys/CN=EM OV CS CA - G3B,O=eMudhra BV,C=NL (emSign Root CS CA - G3).key>) |
| EM OV CS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1) | [crt.sh](https://crt.sh/?sha256=4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1) | [cert](<keys/CN=EM OV CS CA - G3C,O=eMudhra Inc,C=US (emSign Root CS CA - G3).pem>), [key](<keys/CN=EM OV CS CA - G3C,O=eMudhra Inc,C=US (emSign Root CS CA - G3).key>) |

## Cross-signed by Sectigo (AAA Certificate Services)

| Certificate | Censys | crt.sh | Files |
|---|---|---|---|
| EM DV TLS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe) | [crt.sh](https://crt.sh/?sha256=45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe) | [cert](<keys/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.pem>), [key](<keys/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.key>) |
| EM OV TLS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699) | [crt.sh](https://crt.sh/?sha256=5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699) | [cert](<keys/CN=EM OV TLS CA - G3B,O=eMudhra BV,C=NL.pem>), [key](<keys/CN=EM OV TLS CA - G3B,O=eMudhra BV,C=NL.key>) |
| EM EV TLS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512) | [crt.sh](https://crt.sh/?sha256=579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512) | [cert](<keys/CN=EM EV TLS CA - G3B,O=eMudhra BV,C=NL.pem>), [key](<keys/CN=EM EV TLS CA - G3B,O=eMudhra BV,C=NL.key>) |
| EM DV TLS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72) | [crt.sh](https://crt.sh/?sha256=62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72) | [cert](<keys/CN=EM DV TLS CA - G3C,O=eMudhra Inc,C=US.pem>), [key](<keys/CN=EM DV TLS CA - G3C,O=eMudhra Inc,C=US.key>) |
| EM OV TLS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489) | [crt.sh](https://crt.sh/?sha256=7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489) | [cert](<keys/CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US.pem>), [key](<keys/CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US.key>) |
| EM EV TLS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f) | [crt.sh](https://crt.sh/?sha256=fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f) | [cert](<keys/CN=EM EV TLS CA - G3C,O=eMudhra Inc,C=US.pem>), [key](<keys/CN=EM EV TLS CA - G3C,O=eMudhra Inc,C=US.key>) |
| EM OV CS CA - G3B (eMudhra BV) | [Censys](https://platform.censys.io/certificates/a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8) | [crt.sh](https://crt.sh/?sha256=a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8) | [cert](<keys/CN=EM OV CS CA - G3B,O=eMudhra BV,C=NL.pem>), [key](<keys/CN=EM OV CS CA - G3B,O=eMudhra BV,C=NL.key>) |
| EM OV CS CA - G3C (eMudhra Inc) | [Censys](https://platform.censys.io/certificates/84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd) | [crt.sh](https://crt.sh/?sha256=84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd) | [cert](<keys/CN=EM OV CS CA - G3C,O=eMudhra Inc,C=US.pem>), [key](<keys/CN=EM OV CS CA - G3C,O=eMudhra Inc,C=US.key>) |

PEMs of the eMudhra-issued certificates were taken from
[galadran/we-have-a-problem.com](https://github.com/galadran/we-have-a-problem.com)
(`impacted-intermediates.json`) and checked against the SHA-256 values in the
bug. Each key file's public key matches its certificate.
