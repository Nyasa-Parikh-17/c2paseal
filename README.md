# C2paSeal

A pure-Go **signer and verifier** for [C2PA](https://c2pa.org) Content
Credentials in **JPEG** and **PNG** files. It builds with `CGO_ENABLED=0`.

## What it does

The reference C2PA implementation is the Rust `c2pa-rs` library. Using it
from Go means calling `c2patool` as a separate program or linking c2pa-rs
through CGO. C2paSeal signs and verifies in plain Go instead. It builds a
C2PA 2.4 manifest, embeds it in the image (APP11 segments in JPEG, a `caBX`
chunk in PNG), binds it to the image bytes with a `c2pa.hash.data` hard
binding, signs it with ES256 and can add an RFC 3161 time-stamp. The result
is one statically linked binary, or a Go package, that cross-compiles
anywhere Go does.

It is not the only pure-Go C2PA code: for example
[`richardwooding/c2pa`](https://pkg.go.dev/github.com/richardwooding/c2pa)
(used through its `c2pa-mcp` CLI in [INTEROP.md](INTEROP.md)) also validates
and documents a signing command. C2paSeal's focus is a small, auditable
signer for JPEG and PNG:
- **Few dependencies:** three, plus the standard library.
- **Byte-exact writes:** reserve-and-backfill, with the placeholder-length
  invariant checked in production code.
- **Checked against the oracle:** every result is compared with
  `c2patool`, the C2PA reference tool.

`c2patool` accepts C2paSeal's signed files. On the test corpus, C2paSeal's
verifier agrees with `c2patool` on every file where `c2patool` reports
statuses (see [INTEROP.md](INTEROP.md)).

Dependencies: the Go standard library plus `fxamacker/cbor`,
`veraison/go-cose` and `digitorus/timestamp`.

## Quick start

Requires Go 1.27 or newer. From a clone of this repository (the test
certificates in `testdata/pki` work out of the box):

```sh
git clone https://github.com/Nyasa-Parikh-17/c2paseal && cd c2paseal
CGO_ENABLED=0 go build -o c2paseal ./cmd/c2paseal
./c2paseal sign --cert testdata/pki/leaf-chain.pem --key testdata/pki/leaf.key \
    --in testdata/unsigned/small.jpg --out signed.jpg --title "My photo"
./c2paseal verify signed.jpg                                          # state: Valid (signer untrusted)
./c2paseal verify --trust testdata/pki/trust-anchors.pem signed.jpg   # state: Trusted
./c2paseal inspect signed.jpg                                         # manifest store as JSON
./c2paseal serve                                                      # demo UI: http://127.0.0.1:8080/
```

On Windows PowerShell, build with
`$env:CGO_ENABLED=0; go build -o c2paseal.exe ./cmd/c2paseal` and run
`.\c2paseal.exe`. Prebuilt binaries for Linux, macOS and Windows are attached
to each [release](https://github.com/Nyasa-Parikh-17/c2paseal/releases).

If port 8080 is taken, run `./c2paseal serve --addr 127.0.0.1:8090`.
Every command takes `-h` and `--json`. Exit codes: 0 success or valid,
1 invalid or failed, 2 usage error. Add `--tsa <url>` to `sign` for an
RFC 3161 time-stamp.

### As a library

```sh
go get github.com/Nyasa-Parikh-17/c2paseal
```

```go
chain, key, err := c2paseal.LoadSigner("chain.pem", "key.pem")
if err != nil {
	log.Fatal(err)
}
err = c2paseal.Sign("in.jpg", "out.jpg", &c2paseal.SignOptions{Chain: chain, Signer: key})
if err != nil {
	log.Fatal(err)
}
anchors, err := c2paseal.LoadTrustAnchors("roots.pem")
if err != nil {
	log.Fatal(err)
}
result := c2paseal.VerifyFile("out.jpg", &c2paseal.VerifyOptions{TrustAnchors: anchors})
fmt.Println(result.State()) // Invalid, Valid or Trusted
```

Runnable examples: `go doc -ex github.com/Nyasa-Parikh-17/c2paseal Sign`
(also `Read`, `Verify`, `VerifyFile`), or the package page on pkg.go.dev.

## Scope

| Area | Supported |
|---|---|
| Formats | JPEG (APP11 / JPEG XT), PNG (`caBX`) |
| Operations | Read, verify, sign |
| Signature | ES256 (ECDSA P-256, SHA-256) |
| Hard binding | `c2pa.hash.data` |
| Assertions written | `c2pa.actions.v2` (`c2pa.created` plus later actions), `c2pa.hash.data`, optional `c2pa.thumbnail.claim` |
| Time-stamps | RFC 3161 `sigTst2`, verified when present, optional when signing |
| Specification | C2PA 2.4, pinned in [SPEC.md](SPEC.md) |

## Limits

- **The test certificates are untrusted.** `testdata/pki` is a TEST ONLY PKI
  whose private keys are public. Files signed with it prove nothing and show
  `signingCredential.untrusted` unless you pass its root as a trust anchor.
  For real use you need a certificate from a CA on the C2PA trust list.
- **JPEG and PNG only.** No video, BMFF or other formats.
- **ES256 only**, for signing and for verifying claim signatures.
- **One hard binding:** `c2pa.hash.data`. No soft bindings or watermarks,
  no remote manifests, no OCSP/CRL revocation checks, no C2PA 1.x (claim v1)
  manifests.
- A new signature replaces any existing manifest; it does not record the
  previous one as an ingredient. No auto-generated thumbnails.
- A time-stamped file reserves about 10 KiB for the token, whatever its real
  size. Without a time-stamp, validators check the certificate against the
  current time.

## More

- [INTEROP.md](INTEROP.md): results of C2paSeal, `c2patool` and `c2pa-mcp`
  on the corpus and on C2paSeal's own signed files, with the cause of every
  disagreement. Regenerate it with `go run ./interop`.
- [PROGRESS.md](PROGRESS.md): design notes and the build log.
- `testdata/`: fixtures and the `c2patool` output they are checked against.

Licensed under the [Apache License 2.0](LICENSE).
