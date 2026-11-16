# C2paSeal

**Sign and verify C2PA Content Credentials in pure Go.**

[![ci](https://github.com/Nyasa-Parikh-17/c2paseal/actions/workflows/ci.yml/badge.svg)](https://github.com/Nyasa-Parikh-17/c2paseal/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Nyasa-Parikh-17/c2paseal.svg)](https://pkg.go.dev/github.com/Nyasa-Parikh-17/c2paseal)
[![Release](https://img.shields.io/github/v/release/Nyasa-Parikh-17/c2paseal)](https://github.com/Nyasa-Parikh-17/c2paseal/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

C2paSeal reads, verifies and **signs** [C2PA](https://c2pa.org) Content
Credentials in **JPEG, PNG, WebP, HEIC and AVIF** images. It builds with
`CGO_ENABLED=0` into one static binary or a Go package, with no Rust
toolchain, C library or external tool.

**[Try it in your browser →](https://nyasa-parikh-17.github.io/c2paseal/app/)**
It is the same library compiled to WebAssembly. Your files never leave your
machine.

**[Read the documentation →](https://nyasa-parikh-17.github.io/c2paseal/docs/)**
It starts with a five-minute [quickstart](docs/quickstart.md).

---

## Why C2paSeal

The reference C2PA implementation is the Rust library `c2pa-rs`. From Go,
that means running `c2patool` as a separate program or linking Rust through
CGO. C2paSeal does it in plain Go, with a focus on a **small, auditable
signer**:

- **Checked against the reference.** Every result is compared with
  `c2patool`. On 122 test files, C2paSeal agrees with it wherever
  `c2patool` gives a verdict. [INTEROP.md](INTEROP.md) has the full
  results across four validators.
- **Byte-exact.** Signing reserves the manifest's space, then fills it in.
  Production code checks that the final manifest has exactly the
  placeholder's length.
- **Few dependencies.** The core module uses three (`fxamacker/cbor`,
  `veraison/go-cose`, `digitorus/timestamp`) plus the standard library.
  Cloud SDKs and image libraries live in separate modules.
- **Safe on hostile input.** Malformed files become C2PA failure codes,
  never panics. Every parser is fuzzed nightly.

Other pure-Go C2PA code exists, such as
[`richardwooding/c2pa`](https://pkg.go.dev/github.com/richardwooding/c2pa).
C2paSeal's focus is the signer.

## Everything in the box

| | | Guide |
|---|---|---|
| **CLI** | `c2paseal sign`, `verify`, `inspect`, batch mode over folders | [Command line](docs/cli.md) |
| **Go library** | `Sign`, `Verify`, `Read`, in memory or on files | [Go library](docs/library.md) |
| **KMS keys** | AWS KMS and Google Cloud KMS through key URIs; the key never leaves KMS | [Keys and KMS](docs/keys.md) |
| **HTTP middleware** | Signs images as they are uploaded to your Go service | [HTTP middleware](docs/middleware.md) |
| **GitHub Action** | Sign or verify images in a workflow | [GitHub Action](docs/github-action.md) |
| **sealsvc** | A self-hosted signing API with API keys, rate limits, audit log and metrics | [Signing service](docs/sealsvc.md) |
| **Web app** | Verify and sign in the browser, offline | [Web app](docs/web-app.md) |
| **Watermark + sealstore** | Get credentials back for a copy that lost them | [Watermark and recovery](docs/watermark.md) |

## Quick start

Download the archive for your system from the
[latest release](https://github.com/Nyasa-Parikh-17/c2paseal/releases/latest)
and unpack it. It includes TEST ONLY certificates, so this works straight
away:

```sh
./c2paseal sign --cert testdata/pki/leaf-chain.pem --key testdata/pki/leaf.key \
    --in photo.jpg --out signed.jpg --title "My photo"

./c2paseal verify signed.jpg                                         # state: Valid (signer untrusted)
./c2paseal verify --trust testdata/pki/trust-anchors.pem signed.jpg  # state: Trusted
./c2paseal inspect signed.jpg                                        # the manifest store as JSON
```

On Windows, use `.\c2paseal.exe`. To build from source with Go 1.27 or newer:
`CGO_ENABLED=0 go install github.com/Nyasa-Parikh-17/c2paseal/cmd/c2paseal@latest`.

### From Go

```sh
go get github.com/Nyasa-Parikh-17/c2paseal
```

```go
chain, key, err := c2paseal.LoadSigner("chain.pem", "key.pem")
if err != nil {
	log.Fatal(err)
}
if err := c2paseal.Sign("in.jpg", "out.jpg", &c2paseal.SignOptions{Chain: chain, Signer: key}); err != nil {
	log.Fatal(err)
}

anchors, err := c2paseal.LoadTrustAnchors("C2PA-TRUST-LIST.pem")
if err != nil {
	log.Fatal(err)
}
res := c2paseal.VerifyFile("out.jpg", &c2paseal.VerifyOptions{TrustAnchors: anchors})
fmt.Println(res.State()) // Invalid, Valid or Trusted
```

### Sign uploads in a Go service

```go
signer, _ := sign.OpenKey(ctx, "awskms:arn:aws:kms:…") // or "file:key.pem"
chain, _ := c2paseal.LoadChain("chain.pem")
signUploads, _ := middleware.Sign(middleware.Config{Options: &sign.Options{Chain: chain, Signer: signer}})
http.Handle("POST /upload", signUploads(uploadHandler)) // the handler receives signed images
```

### Check images in CI

```yaml
- uses: Nyasa-Parikh-17/c2paseal@v0.7.0
  with:
    command: verify
    files: assets/**/*.jpg
    trust: .github/c2pa-trust-list.pem
```

More in [examples/](examples): an upload server, a folder checker, and
watermark recovery.

## Supported formats

| Format | Manifest location | Hard binding | Read | Verify | Sign |
|---|---|---|---|---|---|
| JPEG | APP11 segments | `c2pa.hash.data` | ✓ | ✓ | ✓ |
| PNG | `caBX` chunk | `c2pa.hash.data` | ✓ | ✓ | ✓ |
| WebP | RIFF `C2PA` chunk | `c2pa.hash.data` | ✓ | ✓ | ✓ |
| HEIC / HEIF | ISO BMFF `uuid` box | `c2pa.hash.bmff.v3` | ✓ | ✓ | ✓ |
| AVIF | ISO BMFF `uuid` box | `c2pa.hash.bmff.v3` | ✓ | ✓ | ✓ |

- **Signs** ES256 with claim v2.
- **Verifies** ES256/384/512, PS256/384/512 and Ed25519, and C2PA 1.x
  files.
- **Supports** time-stamps, OCSP, trust lists, edit history (the parent
  ingredient), sidecar and remote manifests, and soft bindings.
- **Targets** C2PA 2.4, pinned in [SPEC.md](SPEC.md).

Details and known limits: [Formats and scope](docs/formats.md).

## What a signature proves

A **Trusted** result means a certificate holder on your trust list signed
the file, and neither the picture nor the manifest has changed since. It
does **not** mean the picture is true: C2PA records what the signer
claims. Read
[what C2PA does and does not prove](docs/what-c2pa-proves.md) before you
rely on it.

> **The test certificates in `testdata/pki` are TEST ONLY.** Their private
> keys are public, so anything signed with them proves nothing. For real
> use you need a certificate from a CA on the C2PA trust list; see
> [Certificates and trust](docs/certificates.md).

## Repository layout

| Path | |
|---|---|
| `c2paseal.go`, `sign/`, `verify/`, `manifest/`, `container/` | The core module: the library |
| `middleware/` | HTTP middleware that signs uploads |
| `cmd/c2paseal/` | The CLI |
| `action.yml`, `internal/cmd/ghaction/` | The GitHub Action |
| `keys/awskms/`, `keys/gcpkms/` | KMS key providers (separate modules) |
| `cmd/sealsvc/` | Signing service (separate module) |
| `watermark/`, `cmd/sealstore/` | Watermark and manifest store (separate modules) |
| `cmd/c2paseal-wasm/`, `web/` | WebAssembly build and web app |
| `examples/` | Runnable examples (separate module) |
| `docs/` | The documentation site's source |
| `testdata/`, `interop/` | Fixtures with `c2patool`'s output, and the cross-tool harness |

## Project status

C2paSeal is at **v0.7**. Images are complete for the agreed scope; video
(MP4/MOV) comes next, then v1.0.0 and the API freeze.

- [CHANGELOG.md](CHANGELOG.md): what changed in each release.
- [PENDING_APPROVAL.md](PENDING_APPROVAL.md): image features proposed but
  not yet approved.
- [FUTURE_SCOPE.md](FUTURE_SCOPE.md): longer-term directions.
- [PHASES.md](PHASES.md) and [PROGRESS.md](PROGRESS.md): the plan, and the
  build log with test results for every phase.
- [RELEASING.md](RELEASING.md): how releases are made.

Licensed under the [Apache License 2.0](LICENSE).
