# C2paSeal documentation

C2paSeal reads, verifies and **signs** [C2PA](https://c2pa.org) Content
Credentials in JPEG, PNG, WebP, HEIC and AVIF images. It is written in Go
and builds with `CGO_ENABLED=0`: no Rust toolchain, no C library, and no
external tool at run time.

**New here?** The [quickstart](quickstart.md) signs and verifies your first
image in under five minutes. To see it without installing anything, open
the [web app](https://nyasa-parikh-17.github.io/c2paseal/app/). It runs in your
browser, and your files stay on your machine.

## Pick your starting point

| You want to… | Use | Guide |
|---|---|---|
| Sign or check files from a terminal | The `c2paseal` CLI | [Command line](cli.md) |
| Add signing or verification to a Go program | The Go library | [Go library](library.md) |
| Keep the signing key in AWS KMS or Google Cloud KMS | Key providers | [Keys and KMS](keys.md) |
| Sign images as users upload them | HTTP middleware | [HTTP middleware](middleware.md) |
| Sign or check images in a CI workflow | GitHub Action | [GitHub Action](github-action.md) |
| Give other services a signing API | `sealsvc` | [Signing service](sealsvc.md) |
| Check files in a browser, offline | Web app / WebAssembly | [Web app](web-app.md) |
| Find credentials again after they were stripped | Watermark + `sealstore` | [Watermark and recovery](watermark.md) |

## Before you rely on it

Read [what C2PA does and does not prove](what-c2pa-proves.md). A valid
signature says who signed a file and that it has not changed since. It
does not say the picture is true.

## What makes C2paSeal different

- **A signer, not only a reader.** Other pure-Go C2PA code exists, such as
  [`richardwooding/c2pa`](https://pkg.go.dev/github.com/richardwooding/c2pa).
  C2paSeal's focus is a small, auditable signer.
- **Checked against the reference tool.** Every result is compared with
  `c2patool`, built on the C2PA reference implementation (c2pa-rs).
  [INTEROP.md](../INTEROP.md) has the results across four validators.
- **Byte-exact writes.** Signing reserves the manifest's space, then fills
  it in. Production code checks that the final manifest has exactly the
  placeholder's length.
- **Few dependencies.** The core module uses the Go standard library plus
  `fxamacker/cbor`, `veraison/go-cose` and `digitorus/timestamp`. Cloud
  SDKs and image libraries live in separate modules.

The code is on [GitHub](https://github.com/Nyasa-Parikh-17/c2paseal) under
the Apache License 2.0.
