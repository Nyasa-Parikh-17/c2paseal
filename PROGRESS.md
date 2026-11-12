# C2paSeal — progress log

Append one entry per phase: phase number, date, what was built, test results, open issues.

## Future work

Scope-creep ideas go here instead of being built.

- Read claim v1 (`c2pa.claim`, C2PA 1.x files): `claim_generator` string,
  `claim_generator_info` as an array, single `assertions` list.
- Actions rules that need ingredient relationships (c2pa-rs 2.b: opened →
  one `parentOf`, placed → `componentOf`), `c2pa.translated` languages,
  action/template icons, metadata rules, redaction rules.
- Time-stamps: use the CMS `signingTime` signed attribute when present (as
  c2pa-rs does); tell a bad CMS signature (`timeStamp.untrusted`) apart from
  an unparseable token (`timeStamp.malformed`) — `digitorus/timestamp.Parse`
  reports both as one error.
- Legacy (pre-1.3) ingredient manifest hash fallback; redacted ingredients.
- OCSP / revocation; allowed end-entity lists; BMFF, boxes and collection
  hard bindings.
- Remote manifests: HTTP `Link: rel=c2pa-manifest` discovery (§15.5.3.2);
  extended XMP for packets over 64 KB in JPEG; re-signing a file whose
  only store is a sidecar or remote one (today the parent must be embedded).
- Signing: auto-generated thumbnails (would need image decode/resize),
  component ingredients (`componentOf`, c2pa.placed / removed actions) and
  ingredient thumbnails; the parent ingredient and c2pa.opened were added
  in Phase 18, CreativeWork and other assertions,
  signature algorithms other than ES256, keys in HSMs beyond crypto.Signer.

## Log

### Phase 0 — Scaffold (2026-10-17)

**Built**
- Module `github.com/Nyasa-Parikh-17/c2paseal`; deps `fxamacker/cbor/v2` v2.9.6,
  `veraison/go-cose` v1.3.0, `digitorus/timestamp` (2026-09-14). Held in go.mod
  by `deps.go` (`//go:build tools`) until real code imports them.
- Package tree from CLAUDE.md with `doc.go` in each package; `cmd/c2paseal`
  stub (flag-based, exit 2 on usage) with a test; `interop` stub `main`.
- SPEC.md pinned to C2PA 2.4. Apache-2.0 LICENSE, README, .gitignore.
- `.github/workflows/ci.yml`: build, vet, staticcheck 2026.2.1, test on
  ubuntu/macos/windows with `CGO_ENABLED=0`.

**Results**
- `CGO_ENABLED=0 go build ./... && go test ./...` passes (Go 1.27.1, Windows).
- `go vet ./...` and `staticcheck ./...` clean.
- ci.yml parses as YAML; matrix lists all three OSes.

**Open issues / deviations**
- **Go version is 1.27, not 1.25.** Current `digitorus/timestamp` and its
  dependency `digitorus/pkcs7` require Go 1.27. All of pkcs7's BER-parser
  hardening (2026-08/09) and `id-ecPublicKey` support land after that bump;
  we parse untrusted timestamp tokens, so pinning the 2023 versions to keep
  1.25 was rejected. Go 1.25 is also out of upstream support.
- `c2patool` is not installed locally; Phase 1 needs it.
- Not committed yet; repo initialised on branch `main`.

### Phase 1 — Fixtures and oracle (2026-10-17)

**Built**
- `c2patool` 0.27.21 (c2pa-rs 0.90.21) installed to `~/bin` from the official
  release (SHA-256 checked against the release asset digest).
- `scripts/make-pki.sh`: TEST ONLY ES256 chain (root → intermediate → leaf)
  with C2PA leaf profile (digitalSignature, EKU emailProtection +
  documentSigning), plus a 2020–2021 expired leaf for Go-side tests.
- `scripts/make-fixtures.sh` with Go helpers `scripts/genimages`,
  `scripts/mkbroken`, `scripts/oracle`. c2patool settings pinned to an empty
  file so a user's `c2pa.toml` cannot change the oracle.
- Corpus: 5 unsigned, 8 signed (2 with RFC 3161 timestamps, one 7-segment
  JPEG, one 2-manifest parent/ingredient file), 7 broken. Each has
  `.expected.json` and `.trusted.expected.json`. See `testdata/README.md`.
- `internal/fixtures`: `List`, `ListKind`, `Expected`/`Trusted` loaders,
  `ManifestLabels`, `Codes`.
- `.gitattributes` marks `testdata/**` as binary so line endings never change.

**Results**
- `go test ./internal/fixtures`: 20/20 fixtures load; corpus-size check passes.
- Full `go build`, `go test`, `go vet`, `staticcheck` clean.
- Every broken fixture produces its intended oracle failure (table in testdata/README.md).

**Findings for later phases**
- `--detailed` output already contains `validation_results` (success /
  informational / failure) and `validation_state`; no second oracle run needed.
- Claim v2 as written by c2pa-rs: `claim_generator_info` is a single map, not
  an array; assertions split into `created_assertions` / `gathered_assertions`;
  actions label is `c2pa.actions.v2`; thumbnail label is `c2pa.thumbnail.claim`
  (no `.jpeg` suffix) — Phase 6 must handle these names.
- c2patool inserts APP11 **before** an existing APP1 Exif segment (Phase 4
  insertion rule; `signed/exif.jpg`).
- `c2pa.hash.data` from c2patool has a single exclusion covering all APP11
  segments, and a `pad` field.
- c2patool refuses to sign with an already-expired cert; `expired.jpg` is
  signed with a 90-second cert and the script waits for it to expire.
- c2patool reads `C:/...` trust-anchor paths as URLs; pass relative paths.
- Timestamped fixtures depend on DigiCert's public TSA at generation time
  (`TSA_URL` overrides). Regenerating changes every signed file (new UUIDs,
  signing times), so regenerate the whole corpus at once.

**Open issues**
- `scripts/*.sh` need Git Bash on Windows, OpenSSL 3.4+, GNU or BSD `date`.
- No public C2PA samples in `testdata/samples/` yet (optional).

### Phase 2 — JUMBF box parser (2026-10-17)

**Built** (`container/jumbf`)
- `Box` with `Type`, `Form` (Compact / Extended / ToEnd length encoding),
  `Children` (jumb; first child is always the jumd), `Description` (jumd),
  `Payload` (all other types, raw), plus `Offset` and `Raw` original bytes.
- `Description`: content-type UUID, toggles, label, ID, 32-byte hash,
  private box, and `Extra` trailing bytes, so unusual jumd boxes round-trip.
- `Parse` (exactly one box), `ParseAll`, `Serialize`, `Append`, `Size`.
  Parse shares memory with its input. Nesting capped at 32 levels.
- Helpers: `Label`, `Desc`, `Contents`, `Child`, `Find("c2pa/<m>/c2pa.assertions/c2pa.hash.data")`.
- Errors wrap `ErrTruncated` / `ErrBadLength` / `ErrNoDescription` /
  `ErrTooDeep` / `ErrTopLevel` as `jumbf: parse box at offset N: ...`.

**Results**
- `Serialize(Parse(b)) == b` for 9 hand-built trees (compact, extended,
  to-end, all jumd toggles, unknown box types) and for the real manifest
  stores in all 3 signed PNG fixtures (incl. the 474 KB `large.png` store);
  `Find` locates `c2pa.hash.data` of the oracle's active manifest in each.
- 18 error cases return the expected sentinel; error names the box offset.
- `go test -fuzz=FuzzParse -fuzztime=60s ./container/jumbf`: no failures
  (404k execs; property checked: no panic and exact round trip on success).

**Notes**
- Fuzz seeds skip stores over 64 KiB; seeding the 474 KB store dropped
  throughput to near zero.
- `go test -fuzz` on Windows shows bursts of 0 execs/sec while minimising
  new inputs; total throughput is still adequate.

### Phase 3 — JPEG read (2026-10-17)

**Built** (`container/jpeg`)
- `Segments(b)`: marker walk from SOI to SOS (or EOI), recording marker,
  offset and total length. Skips fill bytes; handles standalone markers
  (TEM, RSTn, SOI, EOI); rejects stuffed 0x00, lengths < 2, overruns.
- `Extract(b) → *Store{Root, JUMBF, Segments}`: decodes JPEG XT APP11 headers
  (`JP`, En, Z), groups by box instance, orders by sequence number, checks
  that sequence numbers run 1..n and every segment repeats the same
  LBox/TBox[/XLBox], writes the header once and concatenates the data, checks
  the declared box length, then parses with `jumbf.Parse`.
- A box instance is the C2PA store when it is a `jumb` whose jumd label is
  `c2pa` (checked on the raw first segment, so a store with broken inner
  boxes is still recognised and reported as an error, not "no manifest").
  Non-JPEG-XT APP11 and other JUMBF instances are ignored.
- Errors: `ErrNotJPEG`, `ErrTruncated`, `ErrBadSegment`, `ErrNoManifest`,
  `ErrMultipleStores`.

**Results**
- All 14 JPEG fixtures agree with the oracle: the 5 signed + 4 readable
  broken files give the same manifest labels as `.expected.json` (incl. the
  2-manifest `edited.jpg`); every file c2patool rejects also errors here
  (unsigned → `ErrNoManifest`, `truncated-app11.jpg` → `ErrTruncated`,
  `bad-jumbf-length.jpg` → jumbf error). No panics.
- `large.jpg` reassembles from 7 APP11 segments.
- 12 hand-built cases: out-of-order, fill bytes, foreign APP11, missing or
  duplicate sequence numbers, lost last segment, two stores, XLBox headers.
- `FuzzExtract` 60 s: no failures (808k execs). (Phase 4 adds the
  dedicated walker fuzz target.)

### Phase 4 — JPEG write + round trip (2026-10-17)

**Built** (`container/jpeg/write.go`)
- `Strip(b)`: removes every APP11 segment of the C2PA box instance (store
  only needs to be recognisable, not valid); everything else is copied as-is.
- `Insert(b, store) → (jpeg, []Segment)`: refuses a JPEG that already has a
  store (`ErrHasManifest`). Layout copied from c2pa-rs `jpeg_io.rs` `write_cai`:
  - store cut into `MaxChunk` = 64,000-byte chunks *including* its own box
    header; segment 1 = CI/En/Z + chunk 1, later segments = CI/En/Z +
    repeated LBox/TBox (16 bytes if XLBox) + chunk. Max Le = 64,018 ≤ 65,535.
  - En = `0x0211`, Z = 1..n.
  - placed after the **last APP0** if any, otherwise right after SOI.
- `SegmentCount(n) = ceil(n / 64000)`; `InsertedSize(n, hdrLen)` gives the
  exact bytes added (needed for Phase 11 sizing).

**Results** — round trip is **byte-for-byte** (not the placement-only fallback)
- `Insert(Strip(f), Extract(f)) == f` for all 9 JPEG fixtures with a readable
  store (5 signed incl. 7-segment `large.jpg` and 2-manifest `edited.jpg`,
  4 broken); returned segment ranges equal `Extract`'s.
- `Strip(signed/X) == unsigned/X` exactly for every signed JPEG (and for
  `bad-jumbf-length.jpg`), i.e. c2patool only adds APP11 segments.
- `SegmentCount` at 0, 1, 63,999, 64,000, 64,001, 128,000, 128,001, …;
  synthetic stores at the same boundaries insert, extract and match
  `InsertedSize`.
- Fuzz 60 s each: `FuzzSegments` (walker invariants, 3.3M execs),
  `FuzzStripInsert` (store survives Strip+Insert, 2.6M execs). No failures.

**Deviation from PHASES.md**
- PHASES.md says insert "after SOI and any APP0/APP1 that must precede them".
  c2pa-rs ignores APP1 and inserts *before* an Exif APP1 when there is no
  APP0 (`signed/exif.jpg`). We follow c2pa-rs: a different placement would
  change the `c2pa.hash.data` exclusion start, so the round trip and the
  oracle comparison would both break. Exif readers still find APP1 in
  practice; revisit only if an interop tool complains.

### Phase 5 — PNG read + write (2026-10-17)

**Built** (`container/png`)
- `Chunks(b)`: walks chunks after the signature up to IEND; bounds-checked;
  records `CRCValid` per chunk. Bytes after IEND are ignored and preserved.
- `Extract(b) → *Store{Root, JUMBF, Chunk}`; `Strip(b)`;
  `Insert(b, store) → (png, Chunk)`; `InsertedSize(n) = n + 12`.
- Insertion point copied from c2pa-rs `png_io.rs`: straight after IHDR
  (which is before the first IDAT, as PHASES.md requires).
- More than one caBX → `ErrMultipleStores` (same as c2pa-rs).

**Results**
- Round trip `Insert(Strip(f), Extract(f)) == f` byte-for-byte for all 4 PNG
  fixtures with a store (`signed/small.png`, `signed/large.png` (474 KB
  store), `signed/ts.png`, `broken/data-flip.png`); `Strip(signed) ==
  unsigned` exactly; manifest labels match the oracle; unsigned → `ErrNoManifest`.
- Every chunk in every fixture has a valid CRC.
- Fuzz 60 s: `FuzzChunks` 2.27M execs, `FuzzStripInsert` 1.65M execs, no failures.

**Decision**
- CRC mismatches are recorded, not errors. c2pa-rs never checks PNG CRCs,
  so rejecting them would make us disagree with the oracle (rule 4). A
  changed byte is still caught by the hard-binding hash in Phase 9.

### Gate A — approved (2026-10-17)
User approved and said they would re-check the results later.

### Phase 6 — Claim and assertions (2026-10-17)

**Built**
- `internal/cbormode`: shared `Dec` (duplicate map keys rejected; `any` maps
  decode as `map[string]any`) and `Enc` (core deterministic) modes.
- `manifest`: `Claim` (v2 field names from spec 2.4: `instanceID`,
  `claim_generator_info`, `signature`, `created_assertions`,
  `gathered_assertions`, `redacted_assertions`, `dc:title`, `alg`,
  `alg_soft`, `specVersion`, `metadata`) with `Raw` original bytes;
  `HashedURI{url, alg, hash}`; `GeneratorInfo` map with `Name()/Version()`;
  `DecodeClaim` checks required fields; `Claim.Encode` (write path).
  `DecodeManifest` / `DecodeStore` find the claim, assertion store and
  signature box; last manifest in the store is the active one.
- `manifest/assertion`: `Decode(box)` by base label (instance suffix
  `__N` stripped): `Actions` (v1 + v2), `DataHash` (exclusions, pad, pad2),
  `CreativeWork` (JSON box, CBOR accepted), `Thumbnail` (bfdb media type +
  bidb data; labels `c2pa.thumbnail.claim[.*]` and `.ingredient[.*]`).
  Unknown labels keep `Value == nil` and their raw box. Decode problems go
  in `Assertion.Err` (wrapping `ErrMalformed`), never fail the manifest.
- `scripts/dumpstore`: prints a store as a box tree with CBOR diagnostics.

**Results**
- All 18 manifests in the 13 readable fixtures decode with no error.
- Every decoded claim field equals the oracle's `claim` value; assertion
  label sets equal the oracle's `assertion_store` keys; decoded actions,
  hash.data and CreativeWork equal the oracle JSON exactly; thumbnail sizes
  match `<omitted> len = N`.
- Error tests: 9 bad claims, 5 bad manifests, 9 bad assertions.
- Encode is deterministic and round-trips; key order is core deterministic.

**Differences from PHASES.md (follow the real files / spec 2.4)**
- CreativeWork is a **JSON** box in c2pa-rs output, not CBOR.
- Thumbnail label is `c2pa.thumbnail.claim` (no `.jpeg`); handled as a prefix.
- Claim v1 (`c2pa.claim`) returns `ErrUnsupportedClaim`. Added to Future work.
- Hashed URIs from c2pa-rs omit `alg`; it is inherited from the claim.
- Assertion jumd boxes carry a private `c2sh` salt box (toggles `0x13`);
  the Phase 2 parser keeps it, so hashed-URI checks in Phase 7 see it.
- Fixed-width CBOR integers for exclusions are deferred to Phase 11.

### Phase 7 — COSE, hashed URIs, manifest JSON (2026-10-17)

**Built**
- `manifest/cose`: `Decode` for tagged (18) or untagged COSE_Sign1 →
  `Sign1{Protected (raw bytes as signed), Headers, Unprotected, Payload,
  Signature, Alg, X5Chain, Timestamps}`. x5chain from the protected header
  (label 33), falling back to unprotected; single bstr or array.
  Time-stamp tokens from `sigTst2` (v2) and `sigTst` (v1) `tstTokens[].val`.
  Decoded with fxamacker/cbor; go-cose is kept for verification in Phase 8.
- `manifest/uri.go`: `Resolve` (absolute `self#jumbf=/c2pa/…` from the store
  root, relative from the manifest), `HashBox`, `NewHash` (sha256/384/512).
  `DecodeStore` fills `Manifest.HashChecks` (one `URICheck` per claim
  reference: alg used, resolved box, match, error). Signature decode errors
  go in `Manifest.SignatureErr` so Phase 8 can report them as statuses.
- `jumbf.Box.Bytes()` / `HeaderLen()`.
- Top level: `Read(path)`, `ReadBytes(b)`, `DetectFormat`, `ManifestStore`
  (`Format`, `Root`, `Manifests`, `Active` = last manifest), and
  `ManifestStore.MarshalJSON` shaped like `c2patool --detailed`.
- `golden_test.go` with the ignore list in one place (`goldenIgnore`).

**Results**
- Golden diff is **clean for all 13 readable fixtures**; only
  `validation_results` / `validation_state` are ignored (Phase 8–9). This
  covers claims, every assertion including out-of-scope ones
  (`c2pa.ingredient.v3`, ingredient thumbnail), and the signature section
  (alg, issuer, common_name, time from the RFC 3161 token).
- `broken/assertion-flip.jpg` reports exactly one hashed-URI mismatch
  (`c2pa.actions.v2`); every other reference in every fixture matches.
- All fixture signatures decode: ES256, 2-cert chain, 64-byte signature.
- COSE decode: 3 valid shapes, 12 malformed cases; URI resolve 7 cases.

**Findings (c2pa-rs behaviour we copy)**
- Hashed-URI hash = hash of the superbox **without its 8-byte LBox/TBox
  header** (jumd incl. `c2sh` salt, then content boxes). Verified on fixtures.
- Report `issuer` / `common_name` are the **last** Organization / CN of the
  signer cert's *subject* (cose_validator.rs), not the cert issuer.
- `time` is the time-stamp's genTime in chrono `to_rfc3339` format
  (`+00:00`, fractional seconds only when non-zero, in 3/6/9 digits).
- Claim JSON = claim CBOR as JSON plus `"claim_version": 2`; assertion
  CBOR/JSON as JSON values; embedded files as `<omitted> len = N`.
- c2pa-rs reserves a fixed 12,117-byte COSE box: unprotected `pad` absorbs
  the slack (relevant to Phase 11–12 sizing).
- `digitorus/timestamp.Parse` checks the token's own PKCS#7 signature (not
  trust); a token failing that is skipped for `time`. Phase 9 does the real
  time-stamp validation.

### Checkpoint test run after Phase 7 (2026-10-17)
- `go mod verify`, `go mod tidy -diff`, gofmt, vet, staticcheck: clean.
- `CGO_ENABLED=0 go test -count=1 -cover ./...`: all pass; library coverage
  84–96% (jumbf 93.6, jpeg 94.4, png 94.7, manifest 93.3, assertion 96.1,
  cose 89.2, top level 84.4).
- vet + test build for linux/darwin × amd64/arm64 with CGO off: ok.
- Oracle reproducibility: re-running `scripts/oracle` on a copy of the corpus
  gives **semantically identical** output for all 40 files. 21 files differ
  byte-wise only in JSON object key order (c2pa-rs `assertion_store` is a
  Rust HashMap). All our comparisons parse the JSON, so this is harmless;
  never compare oracle files as raw bytes.
- Fuzz 30 s each, all six targets: no failures (0.6M–3.1M execs each).

### Phase 8 — Signature and certificate checks (2026-10-17)

**Built** (`verify`)
- `status.go`: in-scope status codes as constants; `KindOf` copies c2pa-rs
  `log_kind` (fixed success and informational sets, everything else
  failure); `Status{Code, URL, Explanation}`.
- `signature.go`: `Signature(m, signingTime, opts) []Status` in c2pa-rs
  order — signature reference (`claimSignature.missing`), manifest label
  (`claim.malformed`), algorithm (`algorithm.unsupported`; only ES256 in
  scope), DER-encoded EC signature (`signingCredential.invalid`),
  certificate profile, trust, then the signature: Sig_structure
  `["Signature1", protected, h'', claim Raw]` verified with go-cose's ES256
  verifier → `insideValidity` + `validated`, or `claimSignature.mismatch`.
- `profile.go`: port of c2pa-rs `check_end_entity_certificate_profile`
  (version, validity at time-stamp or now, signature algorithm, EC curve /
  RSA ≥ 2048, self-signed CA, EKU rules with c2pa-rs's allowed list, key
  usage, AKI/SKI, unhandled critical extensions, end-entity).
- `Options{TrustAnchors, Now}`. No anchors → `signingCredential.untrusted`.
- `deps.go` removed: all three allowed dependencies are now imported.

**Results**
- Signature and credential codes (kind, order and URL) equal the oracle
  for **all 13 readable fixtures in both trust modes (26/26)**, incl.
  `sig-flip.jpg` and `expired.jpg`.
- 7 signature scenarios, 6 structural cases and 16 profile rules tested with
  certificates generated in the test and COSE signed by go-cose.
- Full suite, vet, staticcheck, gofmt clean; `verify` coverage 91.6%.

**Cross-check against c2pa-rs (surprises)**
- `claimSignature.insideValidity` is logged whenever the signature verifies,
  even if the cert is expired: expiry is reported separately as
  `signingCredential.expired` and does not stop verification.
- Without a time-stamp, trust is checked with OpenSSL `NO_CHECK_TIME`: an
  expired but otherwise valid chain is still `signingCredential.trusted`.
  Go's `x509.Verify` always checks time, so we try each certificate's
  notBefore/notAfter and accept if any verifies. Checking only at the
  signer's notBefore failed on `expired.jpg` (its leaf predates the test
  intermediate). Chains with no common validity instant would still differ.
- With a time-stamp, both profile and trust use the time-stamp's time.
- c2pa-rs rejects a DER-encoded ECDSA signature as `signingCredential.invalid`
  (COSE requires raw r|s).
- COSE headers in c2pa-rs output: `alg` and `x5chain` protected;
  `sigTst2` and `pad` unprotected; payload nil — matches our decoder.
- Not ported: issuer/subject unique-ID check (Go's x509 does not expose
  them), OCSP, allowed end-entity lists, ES384/ES512/PS*/Ed25519 (scope).

### Phase 9 — Timestamp, hard binding, CLI verify (2026-10-24)

**Environment incident (fixed)**
- After a week away the build failed with `cannot find package` for every
  external import. Cause: OneDrive had turned all 137 working-tree files
  into cloud-file placeholders (reparse tag `0x9000a01a`); Go 1.27 on
  Windows does not read such files correctly. Copies outside the folder
  built fine. Fixed by rewriting each file in place with identical bytes
  (`git status` clean). It can recur: OneDrive may convert them again.
  Recommended: move the repo out of OneDrive (e.g. `C:\dev\c2paseal`).

**Built**
- `internal/asset`: format detection + extraction shared by Read and Verify.
- `verify/timestamp.go`: RFC 3161 check per c2pa-rs: imprint over a COSE
  CounterSignature structure (sigTst2: the signature as a CBOR bstr;
  sigTst: the claim), TSA cert validity at genTime, TSA profile (no extra
  EKUs) and trust against the same anchors. Statuses are success or
  informational only; the time is used for signer checks only when the TSA
  is trusted (c2pa-rs discards an untrusted time-stamp).
- `verify/claim.go`: full per-claim order — reference/label, time-stamp,
  credential + signature, hashed URIs (`match` / `mismatch` / `missing` /
  `outsideManifest`), undeclared assertions, actions rules (empty array,
  first action created/opened, only-first, created needs
  digitalSourceType, opened/placed/removed need ingredients).
- `verify/ingredient.go`: ingredient walk (manifest hash, `ingredient.manifest.*`,
  unknown provenance, recursive claim checks) and c2pa-rs delta filtering
  (drop statuses equal by code+url+kind to any recorded ingredient result,
  never ones about the active manifest).
- `verify/hardbinding.go`: `c2pa.hash.data` with exclusions (sorted, bounds
  and overlap checked), extra-exclusion informational, remote URL, missing /
  multiple bindings.
- `verify.File(b, opts) *Result` (+ `State()`: Invalid / Valid / Trusted by
  c2pa-rs's rule). Unreadable input never errors: no manifest →
  `claim.missing`, JUMBF damage → `claim.malformed`, multiple stores →
  `claim.multiple`, anything else → `general.error`.
- Top level: `Verify(path, opts) []Status`, `VerifyFile`, `VerifyBytes`,
  `VerifyOptions` (= `verify.Options`), `LoadTrustAnchors`.
- CLI: `c2paseal inspect <file>`, `c2paseal verify [--json] [--trust pem]
  <file>`; flags before or after the file; exit 0 valid, 1 invalid or
  unreadable, 2 usage.

**Results**
- `TestCorpus`: **40/40** fixture × trust-mode pairs match the oracle —
  active-manifest codes, URLs and order per kind, ingredient deltas, and
  `validation_state`. The 8 files c2patool cannot read (5 unsigned,
  truncated APP11, bad JUMBF length) each give exactly one failure status.
- Unit tests: trusted time-stamp (time used → expired signer accepted),
  untrusted / mismatched / garbage / duplicate / out-of-validity tokens;
  10 hard-binding cases; 9 actions cases; reference checks; error mapping;
  state rule. `TestFileMutations`: 6,000 corrupted fixtures, no panic, no
  hang. CLI: exit codes on 8 fixtures, `--json`, `inspect`, usage errors.
- `CGO_ENABLED=0 go build ./cmd/c2paseal` works; `c2paseal verify` runs on
  fixtures. Full suite, vet, staticcheck clean. Coverage: verify 94.0%,
  top level 87.1%, CLI 92.1%.

**Notes**
- `FuzzFile` exists but the Go fuzz engine on Windows manages only tens of
  execs/s for it (each exec < 1 ms outside the engine); hence the
  deterministic mutation test. Re-check fuzz throughput on Linux CI.
- `claim.missing` / `claim.malformed` / `general.error` for unreadable
  files is our mapping; c2patool prints an error instead of statuses.
- Hard-binding-missing URL is the manifest URI (not confirmed against
  c2pa-rs's `claim.uri()`; no fixture exercises it).

### Gate B — approved (2026-10-24)
User approved continuing to signing under the MVP scope: JPEG only, no
time-stamps when signing, test PKI only, no UI / interop / release tooling.

### Phase 10 — Manifest builder (2026-10-24)

**Built** (`sign`)
- `Options`: signer chain (leaf first, no root) + `crypto.Signer`; claim
  generator name/version (default `C2paSeal` / `0.1.0`); actions (default one
  `c2pa.created` with `DigitalSourceType`, default IPTC `digitalCapture`);
  optional `Title` and `Thumbnail`; optional `Rand` for salts/UUIDs.
  `validate` rejects non-P-256 keys, a key that does not match the leaf, and
  action lists our verifier (and c2pa-rs) would flag: first action not
  `c2pa.created`, created/opened later on, created without a source type,
  placed/removed (need ingredients).
- `Build(opts) *Manifest`: store laid out like c2pa-rs — `c2pa` / `urn:c2pa:<uuid>`
  / {`c2pa.assertions` {actions.v2, hash.data, [thumbnail.claim]}, `c2pa.claim.v2`,
  `c2pa.signature`} — with C2PA content-type UUIDs, assertion jumd boxes
  carrying a 16-byte random `c2sh` salt, hashed URIs over each assertion
  box, claim v2 (core deterministic), and a tagged COSE_Sign1 with protected
  `{alg: -7, x5chain}`, empty unprotected header, nil payload and a
  zero-filled 64-byte signature.
- `c2pa.hash.data` is hand-encoded (`hashdata.go`) with **fixed-width 8-byte
  CBOR integers** for exclusion start/length, so its size is the same for
  every value; field offsets are recorded for backfilling. This is valid
  CBOR but intentionally not core deterministic.
- Backfill API used by Phase 11: `SetExclusion`, `SetDigest`, `Seal`
  (re-hash hash.data, update its hashed URI, re-encode claim, sign).
  Every replacement goes through `replacePayload`, which returns
  `ErrSizeMismatch` if a new value is not exactly its placeholder's size.
- `jpeg.WriteStore`: overwrite store bytes in an already inserted JPEG, in
  place, across APP11 segment boundaries (closed-form offset mapping).

**Results**
- Builder → serialise → `jumbf.Parse` + `manifest.DecodeStore` round trip
  passes for 5 option sets (defaults; title + generator; thumbnail; two
  actions with softwareAgent; leaf-only chain): claim fields, assertion set,
  actions, placeholder hash.data, thumbnail, x5chain and zeroed signature all
  read back; every hashed URI matches.
- After SetExclusion/SetDigest/Seal the store keeps its size and the claim
  signature verifies with our verifier. Fixed-width encoding: same size for
  0 and MaxUint64. 12 option-validation cases. Same `Rand` → same bytes.
- `WriteStore` equals re-inserting the modified store, incl. writes that
  straddle segments. Full suite, vet, staticcheck clean; `sign` 88.2%.

### Phase 11 — Reserve-and-backfill (JPEG) (2026-10-24)

**Built**
- `sign.JPEG(in, opts)` following PHASES.md's order exactly:
  1. `build` the manifest with zero-filled placeholders of final size
     (32-byte digest, fixed-width 8-byte exclusion start/length, 64-byte
     ES256 signature); 2. serialise and record the store length;
  3. strip any old store, insert the placeholder (segment count checked
     against the closed-form `jpeg.SegmentCount`, contiguity checked);
  4. `SetExclusion(firstSegment.Offset, InsertedSize)` written in place;
  5. SHA-256 of the file minus the exclusion, `SetDigest` written in place;
  6. `Seal`: re-hash hash.data, update its hashed URI, re-encode the claim,
     sign, write claim and signature in place;
  7. `checkReserved(placeholder, final)` returns `ErrSizeMismatch` if the
     final store length differs; the in-place bytes must also equal a
     fresh serialisation of the final tree and what `jpeg.Extract` reads
     back from the output.
  All in-place writes go through `jpeg.WriteStore`; every replaced value is
  size-checked in production code (`replacePayload` → `ErrSizeMismatch`).
- Top level: `Sign(in, out, opts)` (atomic write via temp file + rename),
  `SignBytes`, `SignOptions` (= `sign.Options`), `LoadSigner` (PEM chain +
  PKCS#8 or SEC1 EC key), `ErrSignFormat` for non-JPEG input.
- CLI: `c2paseal sign --cert --key --in --out [--title] [--source-type]`.
- `scripts/mvp-evidence`: signs every unsigned JPEG fixture and saves the
  signed file, unedited c2patool output (default + test root trusted) and
  our `verify --json` in `testdata/mvp-evidence/`, plus a summary README.
- Corpus/oracle tests now pin "now" to 2026-10-24 (`corpusTime`) so they do
  not break when the test PKI expires in 2031.

**Results — all four MVP "Done when" checks pass**
1. Every unsigned JPEG fixture (exif, large, small) signed by us verifies
   with our `Verify`: only `signingCredential.untrusted`, state Valid;
   with the test root trusted: no failures, state Trusted. `Strip` of the
   output gives the original bytes back.
2. `c2patool --detailed` on each: Valid with only
   `signingCredential.untrusted`; Trusted with no failures when the test
   root is trusted (`TestC2patool`, and saved in `testdata/mvp-evidence/`).
3. `TestMisSizedPlaceholder`: 63-, 65- and 0-byte signature placeholders all
   fail with `ErrSizeMismatch` and no output; `checkReserved` tested directly.
4. `CGO_ENABLED=0 go build ./...` and `go test ./...` pass; vet and
   staticcheck clean. Coverage: sign 87.6%, top level 85.9%, CLI 93.1%.
- Also: re-signing a c2patool-signed file (edited.jpg) replaces its store;
  a 192 KB thumbnail makes a 4+ segment store whose in-place writes cross
  segment boundaries and still verify; flipping an image byte gives
  `assertion.dataHash.mismatch`, flipping a signature byte
  `claimSignature.mismatch`.

**Open issues / known limits**
- CI has never run (repo not pushed). `TestC2patool` skips without c2patool,
  so CI will not repeat the c2patool check.
- `--source-type` defaults to IPTC `digitalCapture` ("taken by a camera");
  that is wrong for edited or generated images — callers should set it.
- Signing tests and CLI tests that sign now use the real clock; they will
  start failing when `testdata/pki` expires (2031-10). Regenerate the PKI
  and corpus before then.
- OneDrive may turn the working tree into cloud placeholders again, which
  breaks `go build` (see Phase 9). Moving the repo out of OneDrive avoids it.

### Phase 12 — Timestamps in signing (2026-11-11)

Gate B had limited the MVP to "no time-stamps when signing"; the user
asked to start Phase 12 on 2026-11-11. Phase 11 re-checked first: build,
tests (incl. `TestC2patool` with c2patool on PATH) green; nothing left.

**Built**
- `Options.TSAURL`, `Options.TSAClient` (nil → 30 s timeout),
  `Options.TimestampReserve` (0 → `DefaultTimestampReserve` = 10 KiB, max
  60000); `ErrBadTSA`, `ErrTimestamp`, `ErrTimestampTooLarge`.
- `sign/timestamp.go`: the token time-stamps the signature, so it can only
  be fetched after step 6, and its length varies by TSA. Chosen: reserve
  the slot. With a TSA set, the COSE unprotected header is always
  `{"pad": bstr, "sigTst2": {"tstTokens": [{"val": token}]}}` encoded to a
  fixed size; the zero-filled `pad` (the key c2pa-rs uses) absorbs the
  difference and is kept ≥ 256 bytes so its CBOR head is always 3 bytes and
  every token length up to the reserve fits exactly. Size mismatches return
  `ErrSizeMismatch` / `ErrTimestampTooLarge` in production code; step 7's
  length check still covers the whole store.
- Request: SHA-256 imprint over the COSE `CounterSignature` structure of
  the signature (same bytes `verify/timestamp.go` checks), random 64-bit
  nonce, `certReq` true. Response checked: granted status and CMS signature
  (`ParseResponse`), imprint, nonce echo, TSA certificate present, size
  within reserve; response body capped at 1 MiB.
- CLI: `c2paseal sign … --tsa <url>`.

**Results**
- `TestTimestampedJPEG` (offline fake TSA via `httptest`, cert issued by
  the test root): every unsigned JPEG fixture verifies Trusted with no
  failures and `timeStamp.validated` + `timeStamp.trusted`, checked a year
  *after the signer expired*; the same file without a token fails with
  `signingCredential.expired` — so our verifier uses the token's time.
  Token genTime read back equals the TSA's time. Tokens of three sizes
  give identical output lengths.
- `TestC2patoolTimestamp`: c2patool Valid (only `signingCredential.untrusted`)
  and, with the test root trusted, Trusted with no failures and
  `timeStamp.validated` / `timeStamp.trusted`.
- `TestTimestampFailures`: HTTP 503, rejection, wrong imprint, wrong nonce,
  no TSA cert, token over reserve, unreachable TSA → error, no output.
  `TestTimestampHeaderSize`: exact size for token lengths across every CBOR
  head boundary, reserve+1 rejected. CLI: failing `--tsa` exits 1, no file.
- Manual live check: signed `unsigned/small.jpg` with
  `http://timestamp.digicert.com` via the CLI; our verifier and c2patool
  give the same statuses as c2patool's own DigiCert-stamped fixture
  `titled-ts.jpg` (Valid / Trusted, `timeStamp.validated`, informational
  `timeStamp.untrusted` since DigiCert's root is not in the test anchors).
- Build, vet, staticcheck, full suite clean. Coverage: sign 86.8%, top
  level 85.9%, CLI 93.1%.

**Open issues**
- Every time-stamped file carries the full reserve (~10 KiB) whatever the
  token's size. A TSA whose tokens exceed 10 KiB needs `TimestampReserve`
  raised (no CLI flag for it yet).
- `Sign` has no `context.Context`; the TSA call is bounded only by the
  HTTP client's timeout.
- The live DigiCert check is manual, not in CI (needs network).

### Phase 13 — PNG signing + fuzzing (2026-11-11)

**Built**
- `sign.PNG`: the same reserve-and-backfill flow, with the store in one
  `caBX` chunk straight after IHDR. The signer is now format-agnostic
  (`sign/embed.go`, a small `container` interface; JPEG and PNG adapters).
  The hard-binding exclusion is the whole chunk (length+type+data+CRC), as
  c2patool's own PNGs have it (`ts.png`: exclusion [33, 42984) = the caBX
  chunk), so the CRC, computed last after every backfill, is outside the
  hash. Step 7 also checks the CRC.
- `png.WriteStore` / `png.UpdateCRC` (in-place writes, out-of-range errors).
- Top level `Sign`/`SignBytes` and the CLI accept PNG; `ErrSignFormat` now
  only for non-JPEG/PNG input.
- New fuzz targets: `manifest.FuzzDecodeClaim`, `manifest.FuzzDecodeStore`
  (with URI resolution and hashing), `cose.FuzzDecode`,
  `assertion.FuzzDecode`, `sign.FuzzSign` (anything signed must verify with
  only `signingCredential.untrusted`). `fixtures.SignedFiles` seeds them.

**Results**
- Signed PNGs (both unsigned fixtures, plus re-signing c2patool's `ts.png`,
  plus a 200 KB thumbnail with a time-stamp) verify in our verifier (Valid /
  Trusted) and in c2patool (`TestC2patoolPNG`, with and without a TSA).
  Image tamper → `assertion.dataHash.mismatch`; signature tamper →
  `claimSignature.mismatch`; mis-sized placeholders → `ErrSizeMismatch`.
- Fuzzing, 5 min per target, 12 targets, ~100 M executions in total:
  jumbf Parse 13.0 M; jpeg Segments 22.3 M, Extract 17.3 M, StripInsert
  11.8 M; png Chunks 6.8 M, StripInsert 6.4 M; manifest DecodeClaim 14.4 M,
  DecodeStore 0.46 M; cose Decode 4.7 M; assertion Decode 1.7 M; sign
  FuzzSign 0.26 M; verify FuzzFile 0.81 M. **No findings**: no crashes,
  hangs or property failures; no crashers to add to `testdata/fuzz`.
- `container/png` coverage 95.2%, sign 86.2%.

### Gate C — approved (2026-11-11)
User asked to continue with Phases 14–15 (fuzz run was half done, all
clean so far; it then finished clean).

### Phase 14 — Interop harness (2026-11-11)

**Decisions (user)**
- richardwooding/c2pa is run as an **external CLI**, `c2pa-mcp`, not added
  to `go.mod`. Verified first that it is real: pkg.go.dev v0.7.1 (MIT),
  public repo; installed with `go install …@latest` → v0.7.1, built on
  `github.com/richardwooding/c2pa v0.22.1`; `verify --json` gives C2PA
  status codes. If it fails to install, the harness shows it as not
  installed — never a silent switch to the library.
- c2patool (the CAI's official CLI, our oracle) is the second validator.

**Built**
- `go run ./interop` regenerates `INTEROP.md` from scratch: every JPEG/PNG
  fixture plus each unsigned fixture signed by C2paSeal (with and without a
  time-stamp from a local test TSA), × C2paSeal / c2patool / c2pa-mcp,
  × default and trusted mode. Report: setup note (install c2pa-mcp first
  and check it; c2patool second), tool versions, comparison rule, matrix,
  and a section per disagreement with container facts computed from the
  bytes (store location, exclusions vs store range, recomputed data hash,
  hashed-URI mismatches, first action, signer validity, TSA) and a cause.
- Causes live in `interop/causes.go`; each matches the exact status pattern
  it explains, so a changed behaviour shows as "unexplained".
- `-require c2patool,c2pa-mcp` fails if a tool is missing; `-strict` fails
  on unexplained disagreements. `internal/testtsa` (shared fake TSA, moved
  out of the sign tests).
- `.github/workflows/interop.yml`: on `v*` tags and manual dispatch;
  installs and checks c2pa-mcp v0.7.1 first, then c2patool 0.27.21 via
  `cargo install` (cached), runs `-require … -strict`, uploads INTEROP.md.

**Results**
- 30 files × 2 modes = 60 checks; 34 agree, 26 disagree, 26 explained,
  0 unexplained. **C2paSeal and c2patool agree on every file where
  c2patool produces statuses.** The disagreements: c2patool exits with an
  error on unreadable files (5 unsigned, 2 broken); for the 2 broken
  containers there is no oracle status (we: `claim.malformed` /
  `general.error`; c2pa-mcp: `claim.missing`); c2pa-mcp treats
  `timeStamp.untrusted` as a failure (c2pa-rs and we: informational);
  c2pa-mcp does not report `assertion.action.malformed` on the tampered
  actions assertion, nor `signingCredential.untrusted` for an expired
  signer.
- Checked: delete INTEROP.md → `go run ./interop` recreates it; with
  c2pa-mcp off PATH the column shows `-` and `-require c2pa-mcp` fails.

**Open issues / deviations**
- No c2pa-rs library wrapper: no Rust toolchain here, and c2patool is
  the c2pa-rs CLI. Listed as "not run" in the report.
- The CI workflow has not run (repo not pushed); the c2patool build via
  cargo is the slow step (cached after the first run).
- c2pa-mcp was installed from `@latest` locally (v0.7.1); CI pins v0.7.1.

### Phase 15 — CLI v1 + demo UI (2026-11-11)

**Built**
- CLI: `inspect`, `verify`, `sign`, `serve`, `version`; every command
  answers `-h` (exit 0) and takes `--json`; with `--json`, errors are
  `{"error": …}` on stdout. Exit codes documented: 0 ok/valid; 1 invalid,
  unreadable or failed; 2 usage or unloadable option files.
- `web` package: `Handler` with `GET /`, `POST /api/verify`,
  `POST /api/sign` (multipart `file`, optional `trust=1`). All logic is the
  library's: the server returns the manifest store (c2patool-shaped JSON),
  flattened statuses with their kind, the state, and for sign the signed
  bytes (re-verified). The embedded page only renders: drop zone, coloured
  statuses, state badge, collapsible manifest tree (text only, no HTML
  injection), download link. TEST ONLY banner on the page; uploads capped
  at 32 MB; CSP header.
- `c2paseal serve [--addr 127.0.0.1:8080] [--pki testdata/pki]`: localhost
  by default; graceful shutdown on Ctrl+C.

**Results**
- `TestDropVerifySignReverify` (HTTP level, JPEG and PNG): unsigned →
  Invalid `claim.missing`; sign → Valid (untrusted) / Trusted with
  trust=1; the downloaded bytes verify and, dropped again, are Trusted.
- Real binary smoke test: `serve` started, `curl` drove verify → sign →
  re-verify for small.jpg and small.png (Trusted, no failures).
- Page script passes `node --check`.
- Full suite, vet, staticcheck clean. Coverage: CLI 94.4%, web 85.9%.

**Open issues**
- **The browser check itself (drag-and-drop and rendering) has not been
  done**: no browser was available to this session. Needs a manual run:
  `c2paseal serve`, open http://127.0.0.1:8080/, drop
  `testdata/unsigned/small.jpg` and `small.png`, press Sign.
- `serve` needs `testdata/pki` (run from the repo root or pass `--pki`);
  the test keys are deliberately not embedded in the binary.

### Phase 16 — Docs + release (2026-11-11)

**Built**
- GoDoc: every exported identifier in the public packages already had a
  doc comment (checked with an AST scan); package overview in `doc.go`
  expanded (entry points, reserve-and-backfill, scope, test PKI warning).
- `example_test.go`: `ExampleRead`, `ExampleVerify`, `ExampleVerifyFile`,
  `ExampleSign`, all with checked `// Output:`. `go doc -ex . Sign` (and
  Read, Verify, VerifyFile) shows them.
- README rewritten: what it is, scope table, limits (test certs untrusted
  first), 10-line CLI quick start, library snippet, link to INTEROP.md.
  The "gap" is stated carefully: richardwooding/c2pa (c2pa-mcp) also
  documents pure-Go signing, so the README does not claim C2paSeal is the
  only CGO-free signer (CLAUDE.md rule 9 spirit).
- `scripts/release.sh <version>`: CGO_ENABLED=0 archives for linux, darwin,
  windows × amd64, arm64, each with README, LICENSE and the TEST ONLY PKI
  (so `serve` works unpacked), plus SHA256SUMS.
- `.github/workflows/release.yml` on `v*` tags: test (build, vet,
  staticcheck, test) → build archives → smoke test the native archive on
  ubuntu, macos, windows (sign + verify Trusted) → `gh release create`.
- `serve` listen errors now suggest `--addr`; README mentions it.

**CI fix**
- `ci.yml` has failed on every push since the repo was pushed: the
  Staticcheck step (before Test) crashed on all three OSes with "export
  data version 5 is greater than maximum supported version 4".
  `setup-go` resolves `go 1.27` to go1.27.4 (local: 1.27.1) and
  staticcheck 2026.2.1 (v0.8.1) cannot read its export data. Reproduced
  locally with `GOTOOLCHAIN=go1.27.4`; staticcheck v0.8.2 (2026.2.2) runs
  clean, and vet + the full test suite pass under go1.27.4. Pin bumped to
  v0.8.2 in ci.yml and release.yml. CI's Test step has therefore never run
  on GitHub until now.

**Results**
- README quick start run copy-pasted in a fresh clone (cloned from the
  local repo, since that is the only change from the published URL):
  build, sign, verify → Valid, verify --trust → Trusted, inspect, serve
  (on this machine port 8080 is taken by the Oracle XE listener, so
  `--addr 127.0.0.1:8090`). The library snippet compiles and prints
  Trusted in a fresh module.
- `scripts/release.sh` built all 6 archives locally; the Windows archive,
  unpacked, signs and verifies Trusted with its bundled PKI. The version
  string comes from VCS stamping (v0.1.0 at the tag).
- Build, vet, staticcheck, full suite clean (go1.27.1 and go1.27.4).

**Open — needs the user**
- Release workflow "green" cannot be shown until the fix is pushed and a
  tag exists. Next: push, confirm `ci` is green, then tag `v0.1.0` and push
  the tag (ask first — PHASES.md).
- Phase 15 browser check still pending.

### Phase 16 — closed (2026-11-12)

The user committed the Phase 16 work and pushed tag `v0.1.0` (commit
e607c78). On GitHub, `ci` on main, plus `ci`, `release` and `interop` on
the tag, are all green. The release is published with 6 archives and
SHA256SUMS. Phase 16's "Done when" checks now pass.

### Phase 17 — Audit and plan (2026-11-12)

**Built**
- Read `PRODUCT_SPEC.md` (2026-11-11) against PROGRESS.md, PHASES.md and
  INTEROP.md.
- Appended "Part 2" to PHASES.md: Phases 17–33, release gates D–J, and a
  list of spec items that were already done. No code changed.

**Spec items already done (left out of the new phases)**
- PNG signing, trust anchors and EKU checks.
- RFC 3161 time-stamps, both verified and written.
- The local `serve` UI.
- The CLI with `--json` and exit codes.
- Fuzz targets on current parsers.
- The interop matrix in CI.
- The release pipeline with checksums.
- Part of the negative fixture set.

**Spec items not assigned to any phase, now added**
- CLI batch mode, added to Phase 19.
- Nightly fuzzing, CHANGELOG and reproducible builds, added to Phase 21.

**Checked**
- Credentio exists: Google's open-source C++ C2PA validator, Apache-2.0,
  announced 2026-08-13, hosted at mediaprovenance.googlesource.com.
  - It validates C2PA 2.2 and 2.4 but cannot sign yet.
  - It builds with Bazel and Clang and has no version numbers.
  - The interop gate in Phase 21 depends on it building in CI. If it does
    not build, it shows as "not installed", the same rule used for
    c2pa-mcp.
- The web UI issues the spec lists are real in `web/index.html`:
  `validation_state` is rendered as given, so an unsigned file shows red
  "Invalid", and `signingCredential.untrusted` is listed as a failure.
  The overlap in (b) could not be seen here because no browser is
  available.

**Conflicts between the spec and CLAUDE.md (need the user)**
1. Hard rule 7 freezes scope to JPEG/PNG, ES256 and `c2pa.hash.data`,
   with no remote manifests, soft bindings or BMFF. Part 2 needs all of
   these. CLAUDE.md must be updated before Phase 18.
2. Hard rule 9 forbids claiming "zero dependencies", but the spec calls
   the core "zero-dependency". The core module has three dependencies, so
   PHASES.md says "the core module's dependencies stay as they are"
   instead.
3. PKCS#11 needs CGO (hard rule 1). This is decided in Phase 24.
4. Commits: the spec says each phase ends with a commit with no
   attribution lines. Earlier the user said "leave committing to me".

**Open decisions from the spec, still open**
- Watermark from scratch or wrapped (Phase 29).
- Manifest store hosting (Phase 30).
- Licence: the repo is Apache-2.0 today.

**Approved (2026-11-12)**
- The plan is approved.
- CLAUDE.md rule 7 now points to PHASES.md (Phases 0–16 plus Part 2) as
  the agreed scope. Anything else needs the user's approval.
- The wording is "few dependencies", never "zero".
- PKCS#11 is deferred and listed under Later. v0.4 covers AWS KMS and
  GCP KMS only, and CGO stays out entirely.
- From Phase 18 on, each phase ends with a local commit with no Claude
  attribution or co-author lines. The user reviews and pushes.
- Phase 28 (PDF) moved to "Later". v0.5 is WebP plus HEIC/AVIF, with
  Gate G now after Phase 27.

### Phase 18 — Ingredients and remote manifests (2026-11-12)

**Built**
- Re-signing keeps the history (`sign/ingredient.go`):
  - When the input already has a manifest store, every manifest in it is
    copied into the new store unchanged. A production check confirms that
    each re-encodes to exactly its original bytes.
  - The new manifest adds a `c2pa.ingredient.v3` assertion with
    `relationship: parentOf`, `dc:format` and `instanceID`.
  - That assertion holds hashed URIs `activeManifest` (the parent manifest
    box) and `claimSignature` (its signature box), using the same hashing
    convention as c2pa-rs, which `TestClaimSignatureHashConvention` checks
    against c2patool's `edited.jpg`.
  - It also holds `validationResults`: the parent as our verifier saw it,
    with `ParentVerify` options (default: no anchors, as c2patool).
  - A leading `c2pa.opened` action carries `parameters.ingredients`. It is
    added in front of the caller's actions; an explicit `c2pa.opened`
    keeps its own parameters.
  - With a parent, `c2pa.created` and `DigitalSourceType` are rejected.
    `Options.NoHistory` (CLI `--no-history`) restores the old behaviour of
    replacing the existing store.
  - An unreadable existing store gives `ErrParent`, unless `NoHistory` is
    set.
  - The reserve-and-backfill size check is unchanged and still runs.
- Remote and sidecar manifests:
  - `container/xmp` reads and writes `dcterms:provenance` with
    `encoding/xml` and in-place text edits, so other XMP properties are
    kept byte for byte.
  - `container/jpeg` handles XMP in APP1 (`XMP`, `SetXMP`), and
    `container/png` handles it in `iTXt`, including compressed packets on
    read.
  - `internal/asset` gained `RemoteURL` and `SetRemoteURL`.
- Signing options:
  - `Options.RemoteURL` (CLI `--remote`) writes the URL into the XMP
    before hashing, so the reference is covered by the hard binding.
  - `Options.Sidecar` (CLI `--sidecar`) does not embed the store. Its
    `c2pa.hash.data` has no exclusions and covers the whole file.
  - The new `sign.Asset` and `c2paseal.SignAsset` return both the file
    and the store. `c2paseal.Sign` writes `SidecarPath(out)`
    (`<name>.c2pa`).
  - `sign.JPEG`, `sign.PNG` and `SignBytes` reject `Sidecar` with
    `ErrSidecar`, because they would lose the store.
- Verifying external stores:
  - `VerifyOptions.ManifestStore` takes an external store.
  - `FetchRemote` and `HTTPClient` are opt-in: by default verifying stays
    offline. Fetches have a 30 s timeout and a 64 MiB cap, and send
    `Accept: application/c2pa`.
  - Order of lookup: embedded store, then sidecar, then XMP URL
    (C2PA 2.4 §15.5.3).
  - A remote store that is not fetched or not reachable gives
    `manifest.inaccessible` (a C2PA 2.4 failure code).
  - `VerifyFile` and `Read` find sidecars by themselves. New
    `ReadStore` decodes a store on its own.
- CLI:
  - `sign` gained `--no-history`, `--remote` and `--sidecar`, and its JSON
    output now reports `manifests`, `sidecar` and `remote_url`.
  - `verify` gained `--manifest` and `--fetch-remote`.
- Fixtures:
  - `scripts/make-remote-fixtures.sh` makes `testdata/remote/` with
    c2patool: embedded plus remote, sidecar-only and remote-only, in JPEG
    and PNG.
  - The oracle runs with the stores served by `scripts/servedir`, a
    standard-library file server with a lifetime, because Windows cannot
    always kill it. `scripts/oracle` can regenerate only named
    subdirectories, so the rest of the corpus was not touched.
  - `fixtures.Remote`, `External`, `ExternalStore` and `RemoteClient`
    (which serves `served/` without opening a port) let the corpus tests
    run on these files.
- Interop:
  - The harness serves remote stores on 127.0.0.1:8765.
  - C2paSeal runs with `FetchRemote` there.
  - Three new signed groups: `c2paseal+parent`, `c2paseal+sidecar` and
    `c2paseal+remote`.
  - Each row's container facts now include the XMP reference and the
    sidecar.
  - One new explained cause: c2pa-mcp has no sidecar or remote support
    and reports `claim.missing`.
- Docs: SPEC.md lists ingredients and manifest location as in scope.
  README (scope table and limits), doc.go and testdata/README.md updated.

**Results**
- c2patool 0.27.21 accepts our chains of 2 and 3 manifests on all four
  unsigned fixtures, with failures only `signingCredential.untrusted` (none
  with the test root trusted), and sees every manifest
  (`TestC2patoolIngredientChain`).
- c2patool also accepts our re-signed c2patool files (`edited.jpg`,
  `ts.png`, `titled-ts.jpg`).
- c2patool reads our sidecar next to the file, fetches our remote-only
  store from a local server, and uses the embedded store when both exist:
  Valid, and Trusted with the test root (`TestC2patoolRemote`).
- Our ingredient deltas match c2patool's on its own chain: only
  `ingredient.manifest.validated`.
- TestCorpus matches c2patool on all 6 new fixtures in both modes,
  including the remote-only ones fetched through `RemoteClient`.
- INTEROP.md (regenerated with `-require c2patool,c2pa-mcp -strict`):
  51 files × 2 modes. C2paSeal agrees with c2patool on every file where
  c2patool reports statuses. 54 disagreements, all explained, 0
  unexplained.
- gofmt, build, vet, staticcheck and the full suite are clean. Coverage:
  xmp 94.0%, jpeg 94.8%, png 92.3%, sign 86.9%, verify 92.6%.
- Fuzzing, 2 minutes each with no crashers:
  - New targets: `FuzzProvenance` (848k execs), jpeg `FuzzXMP` (419k),
    png `FuzzXMP` (689k).
  - Changed targets: `FuzzSign`, which now also signs with a sidecar and
    a remote URL, and whose signed seeds go through the parent path
    (29k execs); `FuzzFile`, which reaches the XMP and external-store path
    (4.3k execs, slow while the test suite ran alongside).

**Found along the way**
- The interop harness first gave `small.jpg` and `small.png` the same
  sidecar path, so one store overwrote the other and both tools reported
  `assertion.dataHash.mismatch`. The harness now puts the format in the
  name. The same hazard applies to users with `--sidecar`, since the spec
  names sidecars `<stem>.c2pa`; this is noted in the README.

**Open issues**
- Re-signing a file whose only store is a sidecar or remote one does not
  record it as the parent, because the parent must be embedded. Added to
  Future work.
