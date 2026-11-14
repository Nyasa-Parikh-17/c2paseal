# Changelog

All notable changes to C2paSeal. Versions follow [Semantic Versioning](https://semver.org/);
before v1.0.0 a minor version may change the API.

## Unreleased

### Added
- **Keys outside files.** `sign.KeyProvider` and `sign.OpenKey` open
  signing keys named by URIs; `file:` is built in, and providers register
  themselves when imported.
- **AWS KMS and Google Cloud KMS** providers (`awskms:`, `gcpkms:`), each in
  its own Go module (`keys/awskms`, `keys/gcpkms`) so the core module's
  dependencies do not change. The private key stays in KMS. Signatures are
  verified against the key before use, and Cloud KMS checksums are checked.
- `sign/signtest`: issues TEST ONLY certificates for any key and checks
  that files signed through a `crypto.Signer` verify in C2paSeal and
  c2patool, for testing key providers.
- `LoadChain` (a certificate chain without a key) and
  `sign.ParsePrivateKey`.

- **sealsvc**, a self-hosted signing service (`cmd/sealsvc`, its own
  module):
  - `POST /v1/sign`, `POST /v1/verify`, `GET /healthz` and `GET /metrics`
    (Prometheus text format);
  - hashed API keys with scopes, per-key rate limits, size and concurrency
    limits, and a JSON audit log;
  - keys from files, AWS KMS or Google Cloud KMS;
  - a distroless, non-root container image at
    `ghcr.io/nyasa-parikh-17/c2paseal/sealsvc` for linux/amd64 and arm64,
    and a compose example.

### Changed
- `c2paseal sign --key` also takes a key URI (`file:…`).

## v0.3.0 — 2026-11-14

### Added
- **WebAssembly build** (`cmd/c2paseal-wasm`): verify and sign in the
  browser through `globalThis.c2paseal.verify` / `.sign`, returning the
  CLI's JSON. CI holds the gzipped `.wasm` to a 4 MiB budget and runs it in
  headless Chrome on JPEG and PNG files.
- `ParseSigner`, `ParseTrustAnchors`, `ParseAllowedList` and
  `ParseTrustConfig`: the `Load*` functions on bytes instead of paths.
- **Web app on GitHub Pages** (<https://nyasa-parikh-17.github.io/c2paseal/>):
  drag-and-drop verify with a status banner (valid, signer not on your trust
  list, changed since signing or otherwise not valid, no Content
  Credentials) worded as the spec does ("signed by X, unmodified since …"),
  a provenance graph of the manifests and their ingredients, the raw
  manifest store, and a "Sign a sample" tab with the TEST ONLY demo
  certificate. Everything runs in the browser; a service worker keeps it
  working offline.
- `analyze(bytes, opts)` in the WebAssembly build: the JSON the web app
  shows.

### Changed
- `c2paseal serve` serves the same web app (embedded) and answers it
  through its HTTP API, which returns the same JSON as the WebAssembly
  build. Its page now sends a stricter Content-Security-Policy (no inline
  script or style). In package `web`, `Analysis`, `StatusView` and
  `SignedFile` are now aliases of the shared types, and `Site` returns the
  embedded site.

## v0.2.0 — 2026-11-14

### Added
- **Re-signing keeps the history.** Signing a file that already has
  Content Credentials copies its manifests unchanged and records the old
  active manifest as a `parentOf` ingredient, with a leading `c2pa.opened`
  action. `--no-history` (`Options.NoHistory`) replaces the store instead.
- **Remote and sidecar manifests.** Sign with `--remote <url>` (the URL is
  written to XMP `dcterms:provenance` and covered by the hard binding) or
  `--sidecar` (store written to `<name>.c2pa`). Verifying finds the embedded
  store, then a sidecar, then the XMP URL; fetching is opt-in
  (`--fetch-remote`, `VerifyOptions.FetchRemote`), so verifying stays offline
  by default. `ReadStore` decodes a store on its own.
- **C2PA 1.x manifests** (claim v1) are read and verified, with the c2pa-rs
  rules for 1.x files. Verifying also accepts PS256/384/512, ES384/512 and
  Ed25519 signatures; signing stays ES256.
- **Trust lists**: `--trust` takes the official C2PA trust lists (several
  can be given), `--allowed-list` takes end-entity certificates or their
  SHA-256 hashes, `--trust-config` adds allowed EKUs, all in c2pa-rs's
  formats.
- **OCSP revocation**: stapled OCSP responses are read and checked;
  `--fetch-ocsp` asks the signer's responder online (off by default). When
  signing, `--ocsp` / `--ocsp-response` staples a response inside the
  reserved space.
- **CLI batch mode**: `verify` and `inspect` take several files or folders
  (`--recursive`), one result per file, JSON Lines with `--json`.
- Negative fixtures for every defect class (tampered pixels, bad
  signature, truncated manifest, expired certificate, wrong hash, revoked
  certificate), in JPEG and PNG where the format allows; each is rejected by
  C2paSeal and by c2patool.
- Nightly fuzzing of every fuzz target in CI; crashers are kept as
  artefacts. New targets for external manifest stores and the trust files.
- Interop report: Credentio (Google's C++ C2PA library) is the third
  external validator, next to c2patool and c2pa-mcp, built from a pinned
  commit. Every difference is explained in INTEROP.md.

### Changed
- Time-stamp tokens are checked step by step as c2pa-rs does, with its
  status codes, and a TimeStampResp is accepted as well as a bare token.
- `serve` page: a file without Content Credentials shows a neutral "No
  Content Credentials" state instead of a red "Invalid";
  `signingCredential.untrusted` shows as an amber warning ("signer not on
  your trust list") instead of a red failure; the drop zone no longer
  overlaps the TEST ONLY warning. Library and CLI results are unchanged.
- Release builds are reproducible (see "Checking a release" in the release
  notes and in `scripts/release.sh`).
- GitHub Actions moved to their Node 24 versions.

## v0.1.0 — 2026-11-12

First release.

- Read, verify and sign C2PA Content Credentials in JPEG (APP11) and PNG
  (`caBX`), pure Go with `CGO_ENABLED=0`.
- Verifying: claim and assertion hashes, COSE signature (ES256), certificate
  profile and trust anchors, RFC 3161 time-stamps, `c2pa.hash.data` hard
  binding, with c2patool's status codes.
- Signing: ES256 with reserve-and-backfill, optional RFC 3161 time-stamp.
- CLI `c2paseal` (`inspect`, `verify`, `sign`, `serve`, `version`) and a
  local demo page.
- Interop report against c2patool and c2pa-mcp (INTEROP.md).
