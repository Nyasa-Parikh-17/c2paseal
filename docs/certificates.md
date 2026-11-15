# Certificates and trust

A signature is only as meaningful as the certificate behind it.

## The TEST ONLY certificates

`testdata/pki` (also in every release archive) is a small certificate
authority for trying C2paSeal out: a root, an intermediate, and a signing
certificate with its key. **Their private keys are public.** Files signed
with them prove nothing. Validators, including c2patool and C2paSeal, report
`signingCredential.untrusted` unless you pass the test root as a trust
anchor (`--trust testdata/pki/trust-anchors.pem`).

Use them for development, tests and demos only.

## Signing for real

You need:

1. **An ECDSA P-256 key.** Keep it in a file with tight permissions or,
   better, in a [KMS](keys.md), where it never leaves the service.
2. **A certificate for that key** from a certificate authority whose root is
   on the C2PA trust list, with a profile C2PA accepts (digital signature
   key usage; an extended key usage C2PA allows, such as
   `c2pa-kp-claimSigning`, `emailProtection` or `documentSigning`).
3. **Optionally, a time-stamp authority.** With `--tsa`, validators check
   your certificate at the time of signing, so files stay valid after the
   certificate expires.

The C2PA publishes the trust lists, and how certificate authorities get on
them, at <https://c2pa.org>.

## Verifying against the official trust list

Download the C2PA trust list (and the TSA trust list) as PEM files, then:

```sh
c2paseal verify --trust C2PA-TRUST-LIST.pem --trust C2PA-TSA-TRUST-LIST.pem photo.jpg
```

```go
anchors, _ := c2paseal.LoadTrustList("C2PA-TRUST-LIST.pem")
res := c2paseal.VerifyFile("photo.jpg", &c2paseal.VerifyOptions{TrustAnchors: anchors})
```

Without `--trust`, C2paSeal trusts nothing, as c2patool does by default.
The best result is then **Valid**.

## Revocation

- C2paSeal reads OCSP responses stapled in the manifest, and `sign --ocsp`
  staples one.
- `verify --fetch-ocsp` asks the signer's OCSP responder when nothing is
  stapled.
- Not supported: CRLs, and revocation checks for time-stamp authorities
  and intermediate CAs.
