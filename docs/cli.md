# Command line

`c2paseal` is one static binary. Download it from the
[releases](https://github.com/Nyasa-Parikh-17/c2paseal/releases), or build
it with Go 1.27 or newer:

```sh
CGO_ENABLED=0 go install github.com/Nyasa-Parikh-17/c2paseal/cmd/c2paseal@latest
```

Every command takes `-h`. Exit codes: `0` success or valid, `1` invalid or
failed, `2` usage error.

## sign

```sh
c2paseal sign --cert chain.pem --key key.pem --in photo.jpg --out signed.jpg
```

| Flag | |
|---|---|
| `--cert` | PEM certificate chain: the signer, then intermediates (not the root) |
| `--key` | The signer's ECDSA P-256 private key: a PEM file or a `file:` URI |
| `--in`, `--out` | Input and output: JPEG, PNG, WebP, HEIC or AVIF |
| `--title` | `dc:title` of the claim |
| `--source-type` | IPTC digital source type for the `c2pa.created` action (default: digital capture) |
| `--tsa` | RFC 3161 time-stamp authority URL. Validators then check the certificate at the signing time |
| `--ocsp`, `--ocsp-response` | Staple an OCSP response for the signer, fetched or from a file |
| `--no-history` | Replace existing credentials instead of keeping them as the parent ingredient |
| `--sidecar` | Do not embed the manifest store; write `signed.c2pa` next to the output |
| `--remote` | URL where you will serve the store, written into the file's XMP |
| `--json` | Print the result as JSON |

**Re-signing keeps history.** If the input already has Content
Credentials, they stay in the file. The previous manifest is recorded as
the *parent ingredient*, and the new one starts with a `c2pa.opened`
action.

## verify

```sh
c2paseal verify --trust C2PA-TRUST-LIST.pem photo.jpg
c2paseal verify --json --recursive photos/        # one JSON line per file
```

The result is a list of C2PA status codes and a **state**:

| State | Meaning |
|---|---|
| **Trusted** | Intact, matches the file, and the signer chains to one of your trust anchors |
| **Valid** | Intact and matches the file, but the signer is not on your trust list (`signingCredential.untrusted`) |
| **Invalid** | No credentials, or something failed: a changed file, a bad signature, a broken manifest |

| Flag | |
|---|---|
| `--trust` | PEM trust anchors, such as the official C2PA trust list. Repeat for more files. Without it no signer is trusted |
| `--allowed-list` | End-entity certificates trusted as they are (PEM, or base64 SHA-256 lines), as in c2patool |
| `--trust-config` | Extra EKU OIDs to accept for claim signers |
| `--fetch-ocsp` | Check the signer's revocation online when no response is stapled |
| `--manifest` | A manifest store kept outside the file. A `<name>.c2pa` sidecar is found automatically |
| `--fetch-remote` | Download the store from the URL in the file's XMP, if it has no other |
| `--recursive` | With a folder, include its subfolders |
| `--json` | JSON in c2patool's shape: `validation_results`, `validation_state` |

A malformed or truncated file is never an error. It is reported as
**Invalid** with the reasons.

## inspect

```sh
c2paseal inspect photo.jpg
```

This prints the manifest store as JSON, in the shape of `c2patool
--detailed`: the claims, assertions, ingredients and signature details. It
reads without verifying.

## serve

```sh
c2paseal serve                      # http://127.0.0.1:8080/
```

This runs the [web app](web-app.md) locally. Its "Sign a sample" tab uses
the TEST ONLY certificates in `testdata/pki` (`--pki` to change).

## version

`c2paseal version` prints the version and the Go version it was built with.
Release builds are reproducible. The release notes give the commands to
rebuild an archive and compare it with `SHA256SUMS`.
