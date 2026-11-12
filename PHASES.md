# C2paSeal — build phases for Claude Code

34 phases (0–33), each sized for one Claude Code session. Phases 17–33 are in Part 2 at the end of this file. Give Claude Code one phase at a time:

> Read CLAUDE.md and PROGRESS.md, then do Phase N from PHASES.md. Stop when its "Done when" checks pass and update PROGRESS.md.

Three phases end in a **STOP — human gate**. At a gate, check the results yourself before allowing the next phase.

| Phase | Name | Part | Plan weeks |
|---|---|---|---|
| 0 | Scaffold | Setup | 1 |
| 1 | Fixtures and oracle | Setup | 1 |
| 2 | JUMBF box parser | Container | 2 |
| 3 | JPEG read | Container | 2–3 |
| 4 | JPEG write + round trip | Container | 3–4 |
| 5 | PNG read + write | Container | 4 — **Gate A** |
| 6 | Claim and assertions | Manifest | 4–5 |
| 7 | COSE, hashed URIs, manifest JSON | Manifest | 5–6 |
| 8 | Signature + certificate checks | Verify | 6–7 |
| 9 | Timestamp, hard binding, CLI verify | Verify | 7–8 — **Gate B** |
| 10 | Manifest builder | Sign | 9–10 |
| 11 | Reserve-and-backfill (JPEG) | Sign | 11–12 |
| 12 | Timestamps in signing | Sign | 13 |
| 13 | PNG signing + fuzzing | Sign | 14 — **Gate C** |
| 14 | Interop harness | Release | 15 |
| 15 | CLI v1 + demo UI | Release | 15–16 |
| 16 | Docs + release | Release | 16 |

---

## Phase 0 — Scaffold

**Goal:** an empty but buildable repo with CI.

Tasks:
- `go mod init github.com/<you>/c2paseal`, Go 1.25. Add the three allowed dependencies.
- Create the package tree from CLAUDE.md with a `doc.go` in each package.
- `SPEC.md`: target C2PA revision (fill in the exact version you choose), formats, algorithms, out-of-scope list.
- `PROGRESS.md` with a header and an empty log.
- GitHub Actions workflow: `CGO_ENABLED=0 go build ./...`, `go vet`, `staticcheck`, `go test ./...` on Linux, macOS, Windows.
- `.gitignore`, `LICENSE` (MIT or Apache-2.0, ask the user), short `README.md`.

Done when:
- `CGO_ENABLED=0 go build ./... && go test ./...` passes locally.
- CI workflow file is valid YAML and lists all three OSes.

---

## Phase 1 — Fixtures and oracle

**Goal:** a test corpus where every file has a known-correct answer.

Tasks:
- `scripts/make-pki.sh`: OpenSSL script that creates a test root CA, intermediate and ES256 (P-256) leaf with the key usage and EKUs C2PA requires for signing certs. Output to `testdata/pki/`. Mark clearly as TEST ONLY.
- `scripts/make-fixtures.sh`:
  - Copies unsigned originals (`testdata/unsigned/*.jpg|png`; create small ones with Go's `image` package if none exist).
  - Signs them with `c2patool` and the test PKI → `testdata/signed/`.
  - Adds public C2PA sample files if the user has placed them in `testdata/samples/`.
  - Makes broken variants → `testdata/broken/`: one byte flipped in image data, one in the signature, truncated APP11, expired leaf cert, a JUMBF box with a bad length.
  - Runs `c2patool <f> --detailed` for every file → `<name>.expected.json`.
- `testdata/README.md`: what each fixture is and what result is expected.
- A Go test helper `internal/fixtures` that lists fixtures and loads their expected JSON.

**Needs the user:** `c2patool` installed (`cargo install c2patool` or a release binary). If it is not on PATH, stop and say so.

Done when:
- At least 6 signed, 5 broken and 2 unsigned fixtures exist, each with `.expected.json` (unsigned may have none).
- `go test ./internal/fixtures` loads all of them.

---

## Phase 2 — JUMBF box parser

**Goal:** parse and serialise a JUMBF box tree, independent of file format.

Tasks:
- Generic box: 4-byte length, 4-byte type, 8-byte extended length when length == 1, length 0 = to end.
- `jumd` description box: 16-byte content-type UUID, toggles byte, null-terminated label, optional ID and hash fields per toggles.
- Superbox (`jumb`) tree with children; content boxes (`cbor`, `json`, `bfdb`, `bidb`, `uuid`) kept as raw bytes.
- Keep each box's original bytes and offset so serialisation is exact.
- Helpers: find by label path (`c2pa/<manifest>/c2pa.assertions/c2pa.hash.data`).
- Tests with hand-built boxes; fuzz test `FuzzParse`.

Done when:
- `Serialize(Parse(b)) == b` for hand-built trees.
- `go test -fuzz=FuzzParse -fuzztime=60s ./container/jumbf` finds no panics.

---

## Phase 3 — JPEG read

**Goal:** extract the JUMBF manifest store from any signed JPEG fixture.

Tasks:
- Walk markers from SOI to SOS, recording type, offset, length. Handle fill bytes and standalone markers.
- Find APP11 (`FF EB`) segments with the JPEG XT header (`JP`, box instance, sequence number).
- Group by box instance, order by sequence, concatenate payloads (repeated LBox/TBox appear only once in the output).
- Parse the result with the Phase 2 parser and return the tree plus the byte ranges of all APP11 segments.

Done when:
- For every signed JPEG fixture, the manifest labels found match those in `.expected.json`.
- Truncated-APP11 broken fixture returns an error, no panic.

---

## Phase 4 — JPEG write + round trip

**Goal:** remove and insert manifest stores in JPEGs, exactly.

Tasks:
- `Strip(jpeg) → jpeg` removes all C2PA APP11 segments.
- `Insert(jpeg, jumbf) → (jpeg, segmentRanges)` splits the store into APP11 segments of at most 65,535 bytes including headers, with correct sequence numbers, inserted after SOI and any APP0/APP1 that must precede them.
- `SegmentCount(payloadLen)` as a closed-form function; unit test it at boundary sizes.
- Fuzz test for the marker walker.

Done when:
- For every signed JPEG: `Insert(Strip(f), Extract(f))` equals `f` byte-for-byte (or, if the original layout differs only in placement, `Extract` of the result equals `Extract(f)` and `c2patool` still validates it — record which in PROGRESS.md).
- Fuzz runs 60 s with no panics.

---

## Phase 5 — PNG read + write

**Goal:** same as Phases 3–4 for PNG.

Tasks:
- Walk chunks after the 8-byte signature; validate CRC-32.
- Read the `caBX` chunk; parse its JUMBF.
- `Strip` and `Insert` (`caBX` before the first `IDAT`), returning the chunk's byte range.
- Fuzz test.

Done when:
- Round trip passes for every signed PNG fixture.
- Fuzz runs 60 s with no panics.

### STOP — human gate A
Report: round-trip results for every fixture, fuzz results, any fixture that needed special handling. Wait for approval.

---

## Phase 6 — Claim and assertions

**Goal:** decode the manifest's CBOR into Go types.

Tasks:
- Claim struct with the field names from the pinned spec revision (`claim_generator_info`, `signature`, `created_assertions`, `instanceID`, `alg`, …). Keep the original CBOR bytes alongside the decoded struct.
- Hashed URI type `{url, alg, hash}`.
- Assertions: `c2pa.actions` (v2), `c2pa.hash.data` (including `exclusions` and `pad`), `stds.schema-org.CreativeWork`, `c2pa.thumbnail.claim.jpeg`. Unknown labels kept as raw CBOR.
- Encoding uses `fxamacker/cbor` in a deterministic (core deterministic) mode for the write path.

Done when:
- Every signed fixture's claim and assertions decode with no error.
- Decoded values for the in-scope fields match `.expected.json`.

---

## Phase 7 — COSE, hashed URIs, manifest JSON

**Goal:** a full read-only data model that looks like `c2patool`'s.

Tasks:
- Decode the claim signature box as COSE_Sign1: protected header (`alg`, `x5chain`), unprotected header (timestamp token if present), detached payload, signature bytes. Do not verify yet.
- Resolve `self#jumbf=` URIs to boxes; compute and compare hashes; record mismatches.
- `Read(path) → *ManifestStore` in the top-level package.
- `ManifestStore` marshals to JSON shaped like `c2patool --detailed` for the in-scope fields.
- Golden test: diff our JSON against `.expected.json`, ignoring out-of-scope fields (keep the ignore list in one place).

Done when:
- Golden diff is clean for every signed fixture.
- The flipped-byte-in-assertion case (add a fixture if missing) reports a hashed-URI mismatch.

---

## Phase 8 — Signature and certificate checks

**Goal:** the cryptographic half of `Verify`.

Tasks:
- `verify/status.go`: every in-scope C2PA status code as a constant, with success / informational / failure kind. Result type `{Code, URL, Explanation}`.
- Rebuild COSE `Sig_structure` over the original claim bytes; verify ES256 with the leaf key.
- Build the chain from `x5chain` with `crypto/x509`; check validity, key usage and C2PA EKU rules.
- Trust anchors are configurable (`VerifyOptions.TrustAnchors`). An untrusted but valid chain yields `signingCredential.untrusted`, not a total failure.
- Cross-check that our COSE header handling matches what `c2pa-rs` produces; note any surprises in PROGRESS.md.

Done when:
- Signature and certificate status codes match the oracle for every signed fixture and the flipped-signature and expired-cert broken fixtures.

---

## Phase 9 — Timestamp, hard binding, CLI verify

**Goal:** complete `Verify` and expose it on the command line.

Tasks:
- Verify the RFC 3161 token with `digitorus/timestamp`; when present and valid, use its time for certificate validity checks.
- Hard binding: read `exclusions` from `c2pa.hash.data`, hash the file with those ranges skipped, compare. Emit `assertion.dataHash.match` / `.mismatch`.
- `Verify(path, opts) → []Status`. Malformed files produce failure statuses, never a returned Go error or panic.
- CLI: `c2paseal inspect <file>` (manifest JSON) and `c2paseal verify [--json] [--trust anchors.pem] <file>`; exit code 0 = valid, 1 = invalid, 2 = usage error.
- Corpus test: the full status-code list matches the oracle for every fixture.

Done when:
- 100% of the corpus matches the oracle's status codes.
- `CGO_ENABLED=0 go build ./cmd/c2paseal` works and `c2paseal verify` runs on a fixture.

### STOP — human gate B
Report the full corpus match table. If anything does not match, list each case with its cause. **This is the decision point:** the user chooses whether signing starts (Phase 10) or the project switches to the interop-only fallback (go straight to Phase 14, then 15–16).

---

## Phase 10 — Manifest builder

**Goal:** build a correct, unsigned manifest from options.

Tasks:
- `sign.Options`: signer cert chain + private key (`crypto.Signer`), claim generator name/version, actions (default `c2pa.created`), optional title, optional thumbnail.
- Build assertions and the claim using Phase 6 types; serialise each assertion to CBOR, wrap in JUMBF boxes, compute hashed URIs.
- Assemble a full manifest store tree (no file binding yet).
- Test: build a manifest, serialise it, parse it back with the Phase 7 reader, and get the same values.

Done when:
- Builder → serialise → `Read` round trip passes for several option sets.

---

## Phase 11 — Reserve-and-backfill (JPEG)

**Goal:** `Sign` produces JPEGs that verify. This is the core of the project.

Implement exactly this order:
1. Build the manifest with placeholders: zero-filled 32-byte digest in `c2pa.hash.data`, zero-filled exclusion values at their final encoded size, zero-filled 64-byte ES256 signature in COSE_Sign1.
2. Serialise the full JUMBF store and record its length.
3. Compute APP11 segment count in closed form; insert the placeholder segments into the stripped JPEG.
4. Exclusion ranges are now known; write them in place (same encoded size).
5. Hash the file with the exclusions skipped; write the digest in place.
6. Re-hash the `c2pa.hash.data` assertion box, update its hashed URI in the claim, sign the claim, write the signature in place.
7. Check: final manifest length == placeholder length. If not, return an error.

Also:
- Use fixed-width CBOR integer encoding for exclusion start/length so their size never depends on the value.
- `Sign(in, out, opts)` in the top-level package; CLI `c2paseal sign --cert --key --in --out`.

Done when:
- Signed outputs pass our own `Verify` with no integrity failures (trust warning expected).
- `c2patool` reports no integrity failures on our outputs.
- A unit test proves the length check catches a deliberately mis-sized placeholder.

---

## Phase 12 — Timestamps in signing

**Goal:** add an RFC 3161 timestamp to signed files.

Tasks:
- `Options.TSAURL`. Request a token over the signature bytes as the spec requires.
- Token length varies, so reserve a padded slot of fixed size in the unprotected header (or fetch before sizing). Document the choice in code.
- Offline test path: a fake TSA in tests using `httptest`.

Done when:
- Timestamped outputs verify in our verifier and in `c2patool`, and our verifier uses the token's time.

---

## Phase 13 — PNG signing + fuzzing

**Goal:** sign PNGs and harden every parser.

Tasks:
- Same reserve-and-backfill flow with `caBX` (one chunk, no segmentation; CRC computed after backfill and excluded consistently with the spec).
- Fuzz all parsers 5 minutes each; fix every finding and add the crashing input to the corpus.

Done when:
- Signed PNGs verify in our verifier and `c2patool`.
- No fuzz findings remain open.

### STOP — human gate C
Report: sign → verify results across our verifier and `c2patool`, fuzz summary. Wait for approval.

---

## Phase 14 — Interop harness

**Goal:** the research artifact.

Tasks:
- `interop/run.go` (or a script): for every corpus file and every C2paSeal-signed output, run `c2patool`, a small `c2pa-rs` CLI wrapper (if the user has Rust installed), `richardwooding/c2pa`, and C2paSeal. Collect status codes.
- Generate `INTEROP.md`: a file × tool matrix, then a section per disagreement with the byte-level cause.
- One command regenerates it: `go run ./interop`.
- CI job that runs it on tags (tools installed in the job).

Done when:
- `go run ./interop` regenerates `INTEROP.md` from scratch with no manual steps.

---

## Phase 15 — CLI v1 + demo UI

**Goal:** the demo a viva panel can follow.

Tasks:
- CLI polish: help text, `--json` everywhere, consistent exit codes.
- `c2paseal serve [--addr :8080]`: `net/http` + `embed` page. Drop an image → manifest tree + coloured status codes. "Sign" button signs with the test PKI and shows the re-verified result. All logic calls the library; no logic in the page.
- Label the test PKI as test-only in the UI.

Done when:
- Drop → verify → sign → re-verify works end to end in a browser on a JPEG and a PNG.

---

## Phase 16 — Docs + release

**Goal:** a published, usable library.

Tasks:
- GoDoc on every exported identifier; runnable `ExampleRead`, `ExampleVerify`, `ExampleSign`.
- README: what it is, the precise gap (signing, CGO-free), 10-line quick start, scope, limits (test certs are untrusted), link to `INTEROP.md`.
- GoReleaser (or a plain workflow) building CLI binaries for Linux, macOS, Windows with `CGO_ENABLED=0`.
- Tag `v0.1.0` — **ask the user before pushing the tag**.

Done when:
- `go doc` shows examples, README quick start works copy-pasted, release workflow is green.

---

# Part 2 — from v0.1.0 to v1.0 (Phases 17–33)

Source: `PRODUCT_SPEC.md` (Nyasa Parikh, 2026-11-11). Phase 17 checked that
spec against PROGRESS.md and INTEROP.md; work already done in Phases 0–16
has been left out of the phases below. Every phase still follows CLAUDE.md.
Anything that needs a new dependency goes in a separate Go module, and
only after the user agrees. Each release phase ends with a **STOP — human
gate**: report the results, then ask before pushing the tag.

| Phase | Name | Release |
|---|---|---|
| 17 | Audit and plan | — |
| 18 | Ingredients and remote manifests | v0.2 |
| 19 | Legacy manifests, time-stamp follow-ups, CLI batch mode | v0.2 |
| 20 | Trust lists and revocation | v0.2 |
| 21 | Hardening, web UI fixes, release | v0.2 — **Gate D** |
| 22 | WebAssembly build | v0.3 |
| 23 | Static web app on GitHub Pages | v0.3 — **Gate E** |
| 24 | Pluggable key providers | v0.4 |
| 25 | sealsvc signing server | v0.4 — **Gate F** |
| 26 | WebP | v0.5 |
| 27 | HEIC/AVIF and the ISO BMFF layer | v0.5 — **Gate G** |
| 28 | *(moved to Later: PDF)* | — |
| 29 | Watermark module | v0.6 |
| 30 | Manifest store and recovery | v0.6 — **Gate H** |
| 31 | Integrations and docs site | v0.7 — **Gate I** |
| 32 | MP4/MOV | v1.0 |
| 33 | Video in web app and server, docs freeze | v1.0 — **Gate J** |

Already done before Phase 17, and therefore not repeated below:
- PNG signing (Phase 13).
- Trust anchors, certificate chain and EKU checks (Phase 8).
- RFC 3161 time-stamps: verified (Phase 9) and written when signing
  (Phase 12).
- The local `serve` demo UI (Phase 15).
- CLI sign, verify, inspect, version and serve, with `--json` and exit
  codes (Phase 15).
- Fuzz targets on every current parser: 12 targets, 5 minutes each
  (Phase 13).
- The interop matrix with c2patool and c2pa-mcp, run on tags in CI
  (Phase 14).
- Negative fixtures, partly: data, assertion and signature flips, an
  expired certificate, a bad JUMBF length and a truncated APP11 segment.
- The release pipeline, with cross-compiled `CGO_ENABLED=0` binaries and
  SHA256SUMS (Phase 16).

---

## Phase 17 — Audit and plan

**Goal:** check the product spec against what already exists, and write
the plan for the remaining phases.

Tasks:
- Read PROGRESS.md, PHASES.md and INTEROP.md.
- Mark the spec items that are already done.
- Append Phases 18–33 here.
- Report before writing any code.

Done when:
- This section exists, and the user has approved the plan.

---

## Phase 18 — Ingredients and remote manifests

**Goal:** re-signing keeps the edit history, and manifests can live
outside the file.

Tasks:
- Re-signing a signed file copies its manifest(s) into the new store.
  It adds a `c2pa.ingredient.v3` assertion with `relationship: parentOf`,
  hashed URIs to the parent's claim and signature, and `validationResults`.
  It also adds a `c2pa.opened` action that references the ingredient.
  Placeholder sizes still come from the builder, so the reserve-and-backfill
  check is unchanged.
- An option to keep the current replace behaviour (`--no-history`).
- Remote manifests:
  - Write: a sidecar `.c2pa` file plus a URL in XMP `dcterms:provenance`
    (JPEG APP1, PNG iTXt). The file then carries no embedded store, or
    both.
  - Read: parse that URL. Fetching it is opt-in
    (`VerifyOptions.FetchRemote`, `--fetch-remote`), so `Verify` stays
    offline by default.
- Remote-manifest status codes from SPEC.md.
- Fixtures: chains of two and three signatures, checked against c2patool.
  Get a remote-manifest fixture from c2patool.

Done when:
- c2patool shows the ingredient chain of our re-signed files, with no
  failures beyond `signingCredential.untrusted`.
- Our verifier agrees with c2patool on the new fixtures.
- Interop and fuzz are green.

---

## Phase 19 — Legacy manifests, time-stamp follow-ups, CLI batch mode

**Goal:** read older files, and close the gaps left open in Phases 9 and 12.

Tasks:
- Read claim v1 (`c2pa.claim`, C2PA 1.x). This covers `claim_generator`
  as a string, `claim_generator_info` as an array and a single
  `assertions` list. Read-only: we keep signing claim v2.
- Time-stamps:
  - Use the CMS `signingTime` signed attribute when it is present.
  - Report `timeStamp.untrusted` and `timeStamp.malformed` separately;
    `digitorus/timestamp` merges them into one error today.
- `c2paseal verify|inspect DIR...` walks folders. It writes one result
  per file (JSON Lines with `--json`), takes `--recursive`, and exits 1
  if any file is invalid.
- Fixtures: 1.x files from the public c2pa-rs test corpus (check their
  licence), each with c2patool expected output.

Done when:
- The 1.x fixtures match c2patool.
- A batch run over `testdata/` matches the per-file results.

---

## Phase 20 — Trust lists and revocation

**Goal:** trust decisions that match c2pa-rs.

Tasks:
- Load the C2PA trust list (a PEM bundle) together with c2pa-rs's
  allowed-EKU configuration. Add allowed end-entity certificate lists.
- Full chain validation: path building with several intermediates, and
  certificate profile checks against SPEC.md.
- OCSP:
  - Check the signer certificate online. This is opt-in, so verifying
    stays offline by default.
  - Read stapled OCSP responses (`rVals`) from the COSE unprotected header.
  - Staple a response when signing, inside the reserved header size.
- Add the revocation status codes from SPEC.md. Add a test OCSP responder
  under `internal/`, modelled on `internal/testtsa`.

Done when:
- Revoked, good and unknown OCSP cases match c2patool.
- A file signed by a certificate on the official trust list validates as
  Trusted with that list loaded.

---

## Phase 21 — Hardening, web UI fixes, release v0.2.0

**Goal:** v0.2 meets the spec's quality bar.

Tasks:
- Complete the negative fixture set: tampered pixels, bad signature,
  truncated manifest, expired certificate, wrong hash and revoked
  certificate. Each one must be rejected by C2paSeal and by c2patool.
- Add fuzz targets for every parser added since Phase 13, and run fuzzing
  nightly in CI (`schedule:`), with any crashers kept as artefacts.
- Add Credentio to the interop harness as a third external validator.
  - First confirm that it builds (Bazel and Clang, Linux in CI) and that
    it has a CLI or a small driver.
  - Pin a commit, since it has no version numbers.
  - If it can't be built, show it as "not installed". Never substitute
    another tool for it.
- Bump the GitHub Actions still on Node 20 (`actions/cache`,
  `actions/upload-artifact`, `actions/download-artifact`) to their
  Node 24 majors.
- Web UI fixes on the `serve` page:
  - **(a)** A file with no C2PA manifest shows a neutral "No Content
    Credentials" state, not a red "Invalid".
  - **(b)** The drop zone no longer overlaps the TEST ONLY warning box.
  - **(c)** `signingCredential.untrusted` shows as an amber warning
    ("signer not on your trust list"), not a red failure.

  All three are display changes only: library and CLI results do not
  change.
- Add CHANGELOG.md, and make release builds reproducible (`-trimpath`,
  `-buildvcs`). The release notes say how to check this.

Done when:
- Interop and fuzz are green.
- The UI fixes are checked in a browser.
- The release workflow is green for `v0.2.0`.

### STOP — human gate D
Report: interop matrix (including Credentio or why it is missing), negative
fixtures, fuzz summary. Ask before pushing `v0.2.0`.

---

## Phase 22 — WebAssembly build

**Goal:** the same core runs in the browser.

Tasks:
- `cmd/c2paseal-wasm` (`GOOS=js GOARCH=wasm`, `syscall/js` only) with a
  small JS API: `verify(bytes, opts)` and `sign(bytes, opts)`, both
  returning JSON in the same shape as the CLI.
- A size budget for the gzipped `.wasm` file, enforced in CI. Record TinyGo
  as an option if the standard build is too large.
- A headless browser test in CI covering verify and sign on a JPEG and a
  PNG. Ask before adding a browser test tool.

Done when:
- The browser test passes in CI, and the size budget holds.

---

## Phase 23 — Static web app on GitHub Pages, release v0.3.0

**Goal:** a hosted web app where files never leave the browser.

Tasks:
- Rebuild the `serve` page as a static site over the WASM build:
  - Drag-and-drop verify.
  - A status banner: valid, tampered, untrusted signer, or no Content
    Credentials. It keeps the Phase 21 UI fixes.
  - A provenance (ingredient) graph and a raw manifest view.
  - A "Sign a sample" tab using a clearly labelled demo certificate.
- The wording follows the spec: "signed by X, unmodified since …", never
  "real" or "true".
- `serve` keeps working by embedding the same static site.
- Deploy to GitHub Pages from CI.

Done when:
- The site is live on GitHub Pages and works offline after loading.
- The release workflow is green for `v0.3.0`.

### STOP — human gate E
Report: site URL, browser check, size. Ask before pushing `v0.3.0`.

---

## Phase 24 — Pluggable key providers

**Goal:** signing keys don't have to sit on disk.

Tasks:
- A `sign` key-provider interface over `crypto.Signer`, plus key URIs
  (`file:`, `awskms:`, `gcpkms:`).
- AWS KMS and GCP KMS each go in their own Go module (`keys/awskms`,
  `keys/gcpkms`) so the core module's dependencies stay as they are. Ask
  before adding the SDKs.
- No PKCS#11 in v0.4: Go bindings need CGO, and CGO stays out entirely
  (decided 2026-11-12). It is listed under Later.
- Fake KMS endpoints in tests. A real KMS signs in CI only if the user
  supplies credentials.

Done when:
- Files signed through each provider verify in c2patool.
- The core module's `go.mod` is unchanged.

---

## Phase 25 — sealsvc signing server, release v0.4.0

**Goal:** a self-hosted signing service.

Tasks:
- A `cmd/sealsvc` REST API with `POST /v1/sign`, `POST /v1/verify`,
  `GET /healthz` and `GET /metrics` (Prometheus text format written with
  the standard library).
- API keys, per-key rate limits, a structured audit log (`log/slog`, JSON)
  and request size limits.
- Dockerfile (distroless or scratch, CGO_ENABLED=0), a compose example and
  an image published to GHCR from the release workflow.

Done when:
- CI signs through the server using a KMS key or a fake KMS, and verifies
  the result.
- The release workflow is green for `v0.4.0`.

### STOP — human gate F
Report: API, security notes, audit log sample. Ask before pushing `v0.4.0`.

---

## Phase 26 — WebP

**Goal:** sign and verify WebP.

Tasks:
- `container/webp`: RIFF parser and writer with a `C2PA` chunk,
  byte-exact round trips and `c2pa.hash.data` exclusions.
- A fuzz target, oracle fixtures, and new interop rows.

Done when:
- WebP files pass the same checks as JPEG and PNG, including c2patool.

---

## Phase 27 — HEIC/AVIF and the ISO BMFF layer, release v0.5.0

**Goal:** a reusable BMFF box layer, which Phase 32 needs for video.

Tasks:
- `container/bmff`: box parser and writer (size64, `uuid` C2PA box,
  `meta`/`iloc` offset fix-ups) with byte-exact round trips.
- The `c2pa.hash.bmff.v3` hard binding, for verifying and signing. This
  is a new binding beyond `c2pa.hash.data`.
- HEIC and AVIF use it.
- Fuzz targets, oracle fixtures, and new interop rows.

Done when:
- HEIC and AVIF files signed by us verify in c2patool.
- c2patool-signed HEIC and AVIF files verify in our verifier.
- The release workflow is green for `v0.5.0`.

### STOP — human gate G
Report: per-format interop for WebP, HEIC and AVIF. Ask before pushing
`v0.5.0`.

---

## Phase 29 — Watermark module

**Goal:** an invisible watermark that carries a manifest ID.

Tasks:
- Decide first: write it from scratch, or wrap an open-source watermark
  (the open decision in the spec).
- If from scratch: a DWT-DCT embed and extract in a separate module
  (`watermark/`). Decoding JPEG and PNG uses the standard library; WebP
  decoding would need `golang.org/x/image`, so ask first.
- A robustness harness covering JPEG quality 50–95, resizing, cropping
  and screenshots. Publish the results honestly, failures included.

Done when:
- The harness runs in CI, and its results are published in the repo.

---

## Phase 30 — Manifest store and recovery, release v0.6.0

**Goal:** recover credentials from copies that have had them stripped.

Tasks:
- A soft-binding assertion (`c2pa.soft-binding`) in signed files, linking
  the watermark ID.
- A manifest store service with lookup by watermark ID. It lives in a
  separate module, and choosing its database needs the user's approval.
  Also decide whether it is self-hosted only or has a public instance.
- "Recover credentials" in the CLI and the web app: extract the watermark,
  look up the manifest, and verify it against the image.

Done when:
- The recovery test passes: sign, strip the manifest, re-encode, recover,
  verify.
- The release workflow is green for `v0.6.0`.

### STOP — human gate H
Report: recovery results, robustness table. Ask before pushing `v0.6.0`.

---

## Phase 31 — Integrations and docs site, release v0.7.0

**Goal:** easy adoption.

Tasks:
- Go HTTP middleware that signs uploads, built on the Phase 24 key
  providers.
- A GitHub Action that signs or verifies files in a workflow.
- A docs site containing:
  - A quickstart that takes under 5 minutes.
  - A guide per component.
  - An honest "what C2PA does and does not prove" page.
- An examples repository.

Done when:
- A new user gets through the quickstart in under 5 minutes.
- The release workflow is green for `v0.7.0`.

### STOP — human gate I
Report: docs site, Action demo. Ask before pushing `v0.7.0`.

---

## Phase 32 — MP4/MOV

**Goal:** sign and verify video, built on the Phase 27 BMFF layer.

Tasks:
- MP4 and MOV signing and verification with `c2pa.hash.bmff.v3`,
  including fragmented MP4 (Merkle-tree hashes over fragments).
- Fuzz targets, oracle fixtures, and new interop rows.

Done when:
- Plain and fragmented MP4 signed by us verify in c2patool, and
  c2patool-signed MP4 files verify in our verifier.

---

## Phase 33 — Video everywhere, docs freeze, release v1.0.0

**Goal:** v1.0.

Tasks:
- Video in the web app (with size limits) and in sealsvc.
- A full interop pass across all formats and tools.
- Freeze the API docs and state the v1 compatibility promise.

Done when:
- Full interop passes.
- The release workflow is green for `v1.0.0`.

### STOP — human gate J
Report: full interop matrix and API review. Ask before pushing `v1.0.0`.

---

## Later — not scheduled

These items were moved out of Part 2 on 2026-11-12. None of them is built
without the user's approval.

- **PDF (formerly Phase 28).** A minimal PDF reader and writer covering
  only what C2PA needs: an embedded-file manifest store attached through
  an incremental update, plus hard-binding exclusions, a fuzz target,
  oracle fixtures and interop rows.
- **PKCS#11 HSM keys.** Go bindings need CGO, which hard rule 1 forbids.
  This would need a pure-Go approach or a rule change.
