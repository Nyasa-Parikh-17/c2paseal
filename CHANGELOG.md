# Changelog

All notable changes to C2paSeal. Versions follow [Semantic Versioning](https://semver.org/);
before v1.0.0 a minor version may change the API.

## Unreleased

### Fixed
- `Sign` (and `c2paseal sign`) wrote the signed file with owner-only
  permissions (0600) on Linux and macOS, because the temporary file's mode
  survived the rename. A new file now gets 0644, and a replaced file keeps
  its permissions. The data is also flushed to disk before the rename, so a
  crash cannot leave an empty output file.

### Changed
- Code quality, no change in behaviour or output: the manifest builder is
  split into named steps (assertions, claim, signature), proven byte-identical
  with a fixed random source; one shared image-extension check for the CLI
  and the GitHub Action; doc comments that still listed only JPEG and PNG
  (or JPEG, PNG and WebP) now name all five formats.

## v0.7.0 — 2026-11-19

### Added
- **HTTP middleware** (`middleware`): `middleware.Sign` wraps an
  `http.Handler` and replaces each uploaded image with its signed copy. It
  handles multipart file parts and whole-body `image/*` uploads, in JPEG,
  PNG, WebP, HEIC and AVIF. Options: `Prepare` per file, `Fields`,
  `MaxBytes`, `RejectUnsupported`, `ErrorHandler`. `middleware.Files`
  reports what was signed. A failing key or KMS gives 500; a corrupt
  upload gives 422. Standard library only.
- **GitHub Action** (`action.yml`): `uses: Nyasa-Parikh-17/c2paseal@<version>`
  signs or verifies images in a workflow. It takes globs with `**`,
  folders, keys from files or secrets, and `fail-on`
  (invalid/untrusted/never). It writes file annotations, a job summary and
  a JSON Lines report. It builds from the tagged source on Linux, macOS and
  Windows runners. CI runs it on all three.
- **Documentation**: a quickstart, a guide per component, and "What C2PA
  does and does not prove". It is published on the website (below).
- **Examples** (`examples/`, its own module): sign-and-verify,
  upload-server (middleware + key URIs), verify-folder and
  watermark-recover, each with a test.
- `PENDING_APPROVAL.md` (image features awaiting a decision),
  `FUTURE_SCOPE.md` and `RELEASING.md`.
- **The website** moves to its own repository,
  [c2paseal-website](https://github.com/Nyasa-Parikh-17/c2paseal-website), at
  <https://nyasa-parikh-17.github.io/c2paseal-website/>: a home page, the app
  at `/app/` and the docs at `/docs/`, sharing one top bar. The app is
  built from this library at a pinned release. App tabs can be linked:
  `/app/#sign`, `/app/#recover`.
- **Your trust list** in the app: load a PEM file of trust anchors (such as
  the official C2PA trust list). It is used on every tab, kept in the
  browser and never uploaded. Under `c2paseal serve` it is sent with each
  check (form field `anchors`).

### Changed
- The old address, <https://nyasa-parikh-17.github.io/c2paseal/>, now
  publishes `web/moved`: every old URL redirects to the same page on the new
  website (old `?store=` links open the Recover tab), and a service worker
  retires the old offline cache.
- `c2paseal serve` serves the app at `/app/` (`/` redirects there,
  `/docs/…` to the website). Its API moved to `/app/api/verify` and
  `/app/api/sign`. `web.App()` is the app; `web.WebsiteURL` is the
  website.

### Fixed
- `container/bmff`: `Insert` refuses a file whose `ftyp` box has size 0
  (extends to the end of the file). The inserted manifest box would have
  been read as part of `ftyp`. Found by the nightly fuzzer.
- Web app: the offline service worker no longer answers uncached pages
  (such as the docs) with the app. It goes to the network, and falls back
  to the app only when offline.
- The package documentation and the CLI help listed only JPEG and PNG.

## v0.6.0 — 2026-11-15

### Added
- **Invisible watermark** (`watermark/`, its own module): a from-scratch
  DWT-DCT watermark carrying a 64-bit ID with a CRC-32. A robustness
  harness (`cmd/wmharness`) measures JPEG, resizing, cropping, screenshots,
  colour changes and noise, and publishes the results, failures included,
  in `watermark/ROBUSTNESS.md`; CI regenerates and checks them.
- **Soft bindings**: `sign.Options.SoftBindings` records `c2pa.soft-binding`
  assertions (algorithm and value); they are decoded when reading.
- **sealstore** (`cmd/sealstore`, its own module): a self-hosted manifest
  store keyed by watermark ID (files on disk; public lookups, writes with an
  API key, a JSON audit log, a container image). `sealstore sign`
  watermarks, signs with the soft binding and uploads; `sealstore recover`
  reads a copy's watermark, fetches the manifest and verifies it against
  the copy.
- **Recover credentials** in the web app (WebAssembly):
  `extractWatermark()` on pixels decoded by the browser, and `analyze()`
  takes an external manifest store.

### Changed
- `cmd/c2paseal-wasm` is its own Go module (it links the watermark); build
  it from its directory. The web app's Content-Security-Policy allows
  `connect-src https:` and localhost, for the manifest store the user
  names.

## v0.5.0 — 2026-11-15

### Added
- **WebP**: read, verify and sign WebP files (`container/webp`). The store
  is a top-level RIFF `C2PA` chunk, placed last, as c2pa-rs does. Lossy,
  lossless and extended (VP8X) files are supported, as are remote manifest
  references in the XMP chunk. WebP fixtures, negative fixtures, fuzz
  targets and interop rows were added; c2patool agrees on every WebP file.
- **HEIC and AVIF** (`container/bmff`, an ISO BMFF box layer): read, verify
  and sign. The store is a C2PA `uuid` box straight after `ftyp`; inserting
  it moves the absolute offsets in `meta/iloc`. The new hard binding
  `c2pa.hash.bmff.v3` (c2pa-rs's default exclusions, top-level box offsets
  in the hash) is written when signing, and v1-v3 are verified. Fixtures
  from the c2pa-rs corpus, negative fixtures, a fuzz target and interop
  rows; c2patool accepts our HEIC and AVIF files, and we verify c2patool's.
- `c2paseal verify`/`inspect` on folders, the web app and sealsvc accept
  WebP, HEIC and AVIF.

### Fixed
- `c2paseal verify`/`inspect --recursive` skipped files that Windows lists
  as cloud placeholders (OneDrive "Files On-Demand" reparse points in a
  folder that is not one). Such entries are now checked with `os.Stat`.
- The interop report no longer contains local paths from tools' error
  messages.

## v0.4.0 — 2026-11-14

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
