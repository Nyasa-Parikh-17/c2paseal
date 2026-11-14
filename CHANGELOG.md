# Changelog

All notable changes to C2paSeal. Versions follow [Semantic Versioning](https://semver.org/);
before v1.0.0 a minor version may change the API.

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
