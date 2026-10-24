# C2paSeal

A pure-Go, CGO-free **signer and verifier** for [C2PA](https://c2pa.org)
Content Credentials in **JPEG** files. It also reads and verifies PNG.

Pure-Go C2PA readers already exist. C2paSeal adds a signer that needs no
CGO, no Rust toolchain and no external tools: it builds a C2PA 2.4 manifest,
embeds it in the JPEG, binds it to the image bytes (`c2pa.hash.data`) and
signs it with ES256. Its output is accepted by `c2patool`; see
[testdata/mvp-evidence/](testdata/mvp-evidence/).

Dependencies: the Go standard library plus `fxamacker/cbor`,
`veraison/go-cose` and `digitorus/timestamp`.

## Quick start

Requires Go 1.27 or newer.

```sh
CGO_ENABLED=0 go build -o c2paseal ./cmd/c2paseal
```

(PowerShell: `$env:CGO_ENABLED=0; go build -o c2paseal.exe ./cmd/c2paseal`)

**Sign** a JPEG. The repo's test certificates work out of the box:

```sh
./c2paseal sign --cert testdata/pki/leaf-chain.pem --key testdata/pki/leaf.key \
    --in testdata/unsigned/small.jpg --out signed.jpg --title "My photo"
```

**Verify** it. Exit code 0 means valid, 1 invalid, 2 usage error:

```sh
./c2paseal verify signed.jpg                                         # state: Valid (signer untrusted)
./c2paseal verify --trust testdata/pki/trust-anchors.pem signed.jpg  # state: Trusted
./c2paseal verify --json signed.jpg                                  # c2patool-style validation_results
```

**Inspect** the manifest store as JSON (shaped like `c2patool --detailed`):

```sh
./c2paseal inspect signed.jpg
```

From Go:

```go
chain, key, err := c2paseal.LoadSigner("chain.pem", "key.pem")
err = c2paseal.Sign("in.jpg", "out.jpg", &c2paseal.SignOptions{Chain: chain, Signer: key})

result := c2paseal.VerifyFile("out.jpg", &c2paseal.VerifyOptions{TrustAnchors: anchors})
fmt.Println(result.State()) // Invalid, Valid or Trusted

store, err := c2paseal.Read("out.jpg")
```

## Current limits

- **Signing is JPEG only.** PNG files can be read and verified but not signed.
- **No timestamps when signing.** Signed files carry no RFC 3161 time-stamp,
  so validators check the certificate against the current time. Existing
  time-stamps are verified.
- **ES256 (ECDSA P-256) only**, for signing and for verifying claim signatures.
- **The test certificates are untrusted.** `testdata/pki` is a TEST ONLY
  PKI whose private keys are public. Files signed with it show
  `signingCredential.untrusted` unless you pass its root as a trust anchor.
  For real use you need a certificate from a CA on the C2PA trust list.
- A new signature replaces any existing manifest; it does not record the
  previous one as an ingredient. No auto-generated thumbnails.
- Hard binding is `c2pa.hash.data` only. No BMFF, remote manifests, soft
  bindings, OCSP or C2PA 1.x (claim v1) manifests.

Verification follows c2pa-rs and is checked against `c2patool` on a test
corpus (`testdata/`). Design notes and history are in
[PROGRESS.md](PROGRESS.md), scope in [SPEC.md](SPEC.md).

Licensed under the [Apache License 2.0](LICENSE).
