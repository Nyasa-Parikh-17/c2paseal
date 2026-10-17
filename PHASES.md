# C2paSeal — build phases for Claude Code

17 phases, each sized for one Claude Code session. Give Claude Code one phase at a time:

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
