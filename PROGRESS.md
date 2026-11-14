# C2paSeal — progress log

Append one entry per phase: phase number, date, what was built, test results, open issues.

## Future work

Scope-creep ideas go here instead of being built.

- Actions rules that need ingredient relationships (c2pa-rs 2.b: opened →
  one `parentOf`, placed → `componentOf`), `c2pa.translated` languages,
  action/template icons, metadata rules, redaction rules.
- Redacted ingredients (the claimSignature fallback when a redaction breaks
  the ingredient manifest hash).
- Verifying the 1.x verifiable credentials store (`c2pa.credentials`): it is
  shown by `inspect`, not checked.
- Strict v1 validation (c2pa-rs `strict_v1_validation`, off by default): the
  full actions rules on v1 claims.
- Revocation beyond the signer's OCSP: CRLs, OCSP for time-stamp
  authorities, the `c2pa.certificate-status` assertion; BMFF, boxes and
  collection hard bindings.
- Remote manifests: HTTP `Link: rel=c2pa-manifest` discovery (§15.5.3.2);
  extended XMP for packets over 64 KB in JPEG; re-signing a file whose
  only store is a sidecar or remote one (today the parent must be embedded).
- Signing: auto-generated thumbnails (would need image decode/resize),
  component ingredients (`componentOf`, c2pa.placed / removed actions) and
  ingredient thumbnails; the parent ingredient and c2pa.opened were added
  in Phase 18, CreativeWork and other assertions,
  signing with algorithms other than ES256 (verifying them was approved and
  added in Phase 19), keys in HSMs beyond crypto.Signer.
- Web app: load your own trust list (for example the official C2PA trust
  list PEM) in the browser and keep it between visits; today the app trusts
  the demo root or nothing.
- Test PKI: add the `c2pa-kp-claimSigning` EKU (1.3.6.1.4.1.62558.2.1) to
  the TEST ONLY signer. C2PA 2.4 §14.4.1 recommends it, and Credentio
  trusts anchors only for it, so today it stops at `signingCredential.invalid`
  on every test-PKI file in trusted mode and checks nothing else. Needs new
  keys and a full regeneration of the corpus and oracle files.
- Credentio now has a writer (`tools:asset_write`, README of commit
  ee4078b); Phase 17 recorded that it could not sign. Signing-side interop
  (C2paSeal reading Credentio's files) is not in any phase.

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

### Phase 19 — Legacy manifests, time-stamp follow-ups, CLI batch mode (2026-11-13)

**Decision (user, 2026-11-12):** every C2PA 1.x file in the public c2pa-rs
corpus is signed PS256, which SPEC.md had out of scope. The user approved
verify-only support for PS256/384/512, ES384/512 and Ed25519 with the Go
standard library; signing stays ES256. SPEC.md and README updated.

**Built**
- Signature algorithms (`verify/alg.go`): ES256/384/512 (raw r|s, the curve
  must match the algorithm), PS256/384/512 (RSASSA-PSS, salt length = digest
  length, as c2pa-rs), Ed25519. Certificates with an id-RSASSA-PSS key,
  which Go's x509 leaves unparsed, are read by hand, and the profile's
  2048-bit minimum applies to them. The DER-signature check applies to the
  EC algorithms only. Unknown algorithms still give `algorithm.unsupported`.
- Claim v1 (`manifest.DecodeClaimV1`, label `c2pa.claim`), following c2pa-rs
  `Claim::from_value`: only v1 keys; `claim_generator`, `signature`,
  `assertions`, `dc:format` and `instanceID` required. `Claim.Version`
  is 1 or 2; the v1 fields (`ClaimGenerator`, `GeneratorInfoV1`, `Format`,
  `V1Assertions`, `ClaimGeneratorHints`) are kept apart, and
  `ClaimGeneratorInfo` holds the first `claim_generator_info` entry (or the
  generator string). `Assertions()` returns the v1 list. `Encode` still
  writes v2 only. `ErrUnsupportedClaim` is no longer returned.
- v1 rules in `verify`, each from c2pa-rs:
  - no `urn:c2pa:` label check (1.x used `urn:uuid:`);
  - actions: only "one actions assertion"; the other rules are skipped
    (`strict_v1_validation` is off by default);
  - time-stamps: the authority's trust is not checked (claim.rs turns off
    `verify_timestamp_trust` for v1), so a valid v1 token is
    `timeStamp.trusted` and its time is used for the signer checks;
  - pre-1.3 ingredient hash: if the hash does not match the manifest box,
    a hash of the ingredient's claim bytes is accepted, logging nothing.
    This was a separate Future work item; it is needed to read 1.x files
    and is two cases in one switch, so it was done here.
- `cose.Decode` finds `x5chain` as c2pa-rs does: label 33 or text
  `"x5chain"` in the protected header, only text `"x5chain"` in the
  unprotected one, and not both. (c2pa-rs 0.16 files use the text label.)
- Prerelease (pre-1.0) stores: `verify.IsPrerelease` applies c2pa-rs's
  test (the first assertion's claim hash is over its payload alone). `File`
  reports `com.adobe.prerelease` as the one failure, `Read` returns
  `ErrPrerelease`; c2patool refuses such files.
- Found while matching 1.x files, not 1.x specific: c2pa-rs's pre-pass
  `get_claim_referenced_manifests` logs `ingredient.manifest.missing` in the
  active manifest's results for every ingredient manifest the tree
  references but the store lacks, before any claim is checked.
  `referencedManifests` does the same.
- Time-stamps (`verify/tst.go`): a small CMS SignedData reader (standard
  library `encoding/asn1`) replaces `digitorus/timestamp.Parse` on the
  verify path, so each step follows c2pa-rs `verify_time_stamp`:
  unreadable token or no TSTInfo/messageDigest → `timeStamp.malformed`;
  no certificates, or a CMS signature that does not verify →
  `timeStamp.untrusted`; messageDigest or imprint mismatch →
  `timeStamp.mismatch`. The CMS `signingTime` attribute replaces genTime
  when present. A TimeStampResp is accepted as well as a bare token (c2pa-rs
  1.x files store the response). The CMS signature scheme follows the TSA
  key type and the SignerInfo digest, as c2pa-rs's
  `validator_for_sig_and_hash_algs`. `digitorus/timestamp` stays on the
  signing path.
- `verify.SigningTime`: the time of a token valid for the signature,
  whatever the TSA's trust, as c2patool's `signature.time`; the report now
  omits it when the token does not match (E-sig-CA.jpg).
- Report (`inspect`, `MarshalJSON`): the real `claim_version`; v1 files
  without `claim_generator_info` show `[]`; hashed-URI hashes stored as
  integer arrays (old c2pa-rs, JSON assertions) shown as base64, as
  c2patool does; the 1.x `credential_store`.
- CLI batch mode (`cmd/c2paseal/batch.go`): `verify` and `inspect` take
  several files or folders. A folder gives its `.jpg`/`.jpeg`/`.png`
  files, sorted, and its subfolders' with `--recursive`. One result per
  file: a line (plus failure codes) and a summary for `verify`, JSON Lines
  with `--json` (`inspect` always). Exit 1 if any file is invalid or
  unreadable. A single file behaves as before; `--manifest` stays
  single-file.
- Fixtures: `scripts/make-legacy-fixtures.sh` builds `testdata/legacy/`:
  10 files from the c2pa-rs corpus at a pinned commit, checked by SHA-256
  (MIT OR Apache-2.0), and 3 v1 files written by c2patool with the test
  PKI (`"claim_version": 1`): `v1.jpg`, `v1.png`, `v1-edited.jpg` (a v1
  chain). `fixtures.Legacy`; `scripts/oracle` knows `legacy`. `cloud.jpg`
  was left out: its store is only at an Adobe URL.
- Interop: the legacy files are in INTEROP.md. Five new explained causes,
  all c2pa-mcp or "no oracle": it checks TSA trust on v1 claims; it reports
  ingredient failures already recorded in the ingredient assertion; it calls
  a missing ingredient manifest a mismatch; it classifies
  `timeStamp.mismatch` as a failure; and for `prerelease.jpg` c2patool
  refuses the file. Container facts now show the claim version and read
  TimeStampResp-wrapped tokens.
- Tests: `TestAlgorithms` (all seven algorithms signed by go-cose, wrong key
  type and curve), `TestPSSKey`, `TestDecodeClaimV1`, the time-stamp cases
  (signingTime both ways, bad CMS signature, no certificates, messageDigest
  mismatch or missing, no signed attributes, signer not embedded,
  TimeStampResp, v1 trust, and a digitorus token as a cross-check) built
  with a test-only CMS writer so they do not depend on the clock,
  `TestBatchMatchesSingle`, `TestExpand`, `TestVerifyBatchText`,
  `TestSignatureTimeInvalid`. Existing tests adjusted where the corpus grew:
  manifest tests compare v1 claims under their v1 keys; the JPEG layout
  round trip skips `ocsp.jpg` (Photoshop puts APP11 after Exif; Extract is
  still exact); `TestOracle` passes the time-stamp time as `checkClaim` does.
- Fuzz: new `FuzzToken` and `FuzzDecodeClaimV1`.

**Results**
- TestCorpus: all 13 legacy fixtures match c2patool in both modes, kind by
  kind and in order, with ingredient deltas and state; `prerelease.jpg`
  gives exactly one failure where c2patool errors. TestGolden (the JSON
  report) and the manifest fixture tests match the oracle on them too.
- Batch: a recursive `verify --json` over `testdata/` gives, for every
  image, exactly the single-file result, in both trust modes; `inspect`
  likewise.
- INTEROP.md (`-require c2patool,c2pa-mcp -strict`): 64 files × 2 modes,
  C2paSeal agrees with c2patool on every file where c2patool reports
  statuses; 74 disagreements, all explained, 0 unexplained.
- gofmt, build, vet, staticcheck and the full suite are clean. Coverage:
  verify 92.7%, manifest 94.7%, manifest/cose 89.7%, cmd/c2paseal 91.1%,
  root 80.4%.
- Fuzzing, 2 minutes each, no crashers: `FuzzDecodeClaimV1` (3.35M execs),
  `FuzzDecodeStore`, `FuzzFile` (6.9k), `FuzzToken` (53k in one run,
  1.4k in another; fuzzing the instrumented verify package is slow on this
  machine, as `FuzzFile` was in Phase 18).

**Open issues**
- c2pa-rs sets `signature.time` from a passthrough trust policy; we take
  the time of any token valid for the signature. They agree on the corpus.

### Phase 20 — Trust lists and revocation (2026-11-13)

**Built**
- Trust configuration (`verify.Options`), each as c2pa-rs's
  CertificateTrustPolicy:
  - `AllowedList`: SHA-256 of end-entity certificates trusted as they are,
    checked before any chain and also without anchors; reported as "found in
    EndEntity trust anchors". Applies to signers, TSAs and OCSP responders.
  - `ExtraEKUs`: accepted for claim signers on top of the defaults.
  - Loaders: `LoadTrustList` (PEM bundles such as the official
    `C2PA-TRUST-LIST.pem` and `C2PA-TSA-TRUST-LIST.pem`, now in
    `testdata/trust/`, CC BY 4.0), `LoadAllowedList` (PEM certificates or
    44-character base64 hashes outside PEM blocks, as c2pa-rs reads them),
    `LoadTrustConfig` (one OID per line).
  - CLI `verify`: `--trust` repeatable, `--allowed-list`, `--trust-config`.
- Chains: Go's path building already handles several intermediates in any
  order; now checked against c2patool (in order, out of order, middle
  missing, a `pathlen:0` intermediate exceeded).
- OCSP (`internal/ocsp`, standard library only): parse responses and
  requests, verify the response signature with the first embedded
  certificate (as c2pa-rs), match CertIDs, build requests, fetch with GET
  `<url>/<base64 request>` (as c2pa-rs), and write responses (for the test
  responder). openssl verifies our responses (`Response verify OK`).
- `cose.Decode` reads stapled responses from `rVals.ocspVals`.
- Verifying (`verify/ocsp.go`), in c2pa-rs order (after the signature
  reference checks, before the time-stamp and credential checks):
  - stapled: used only if the responder is a valid OCSP signer that is
    trusted (anchors or allowed list); good → informational
    `signingCredential.ocsp.notRevoked`; revoked → c2pa-rs returns an error
    that ends all validation (c2patool prints only "the certificate is not
    trusted"), so `File` reports `signingCredential.ocsp.revoked` as its one
    failure, for the active manifest or an ingredient; unknown → nothing;
  - fetched (`Options.FetchOCSP`, off by default; CLI `--fetch-ocsp`):
    success `notRevoked`, failure `revoked` / `unknown`, informational
    `inaccessible`, with c2pa-rs's URL `OCSP_RESPONSE` and its time rules
    (thisUpdate/nextUpdate, revocation time against a trusted time-stamp,
    removeFromCRL).
  - c2pa-rs logs the same code with different kinds on the two paths and
    c2patool groups by kind, so `Status` gained an unexported kind
    override; all `Status` literals became keyed (`gofmt -r`).
- Signing: `Options.OCSPResponse` (given) or `FetchOCSP` (from the signer's
  AIA responder) staples `rVals` in the unprotected header. The response is
  known before sizing, so it is part of the placeholder and the reserve
  check is unchanged; with a TSA the padded slot includes it. The response
  must parse, be successful, verify and answer for the signer
  (`ErrBadOCSP`); its status is stored as given. CLI `sign --ocsp` /
  `--ocsp-response`, and `ocsp_stapled` in the JSON output.
- Test PKI: `scripts/genocsppki` adds `testdata/pki/ocsp/` (responder and
  good / revoked / unknown signers with AIA `http://127.0.0.1:8766/`) under
  the existing intermediate; other keys untouched. `internal/testocsp` is
  the responder (GET and POST), `scripts/ocspd` serves it with a lifetime.
- Fixtures: c2pa-rs reads stapled responses but never writes them, so
  `scripts/make-ocsp-fixtures.sh` signs `testdata/ocsp/{good,revoked,
  unknown}.jpg` with C2paSeal and c2patool is the oracle. `fixtures.OCSP`;
  its corpus time is 2026-11-20 because the signers were issued this month.
- Report: an empty byte string prints as `[]`, as c2patool does (our own
  signer writes an empty `pad`; these are the first oracle fixtures it made).
- Interop: the OCSP files are in INTEROP.md; container facts show the
  stapled answer (also Adobe's real one in `legacy/ocsp.jpg`); one new
  cause: for `ocsp/revoked.jpg` in trusted mode c2patool refuses the file
  and c2pa-mcp, which does not read stapled responses, finds it Trusted.

**Results**
- Revoked, good and unknown match c2patool, kind by kind, URL and state:
  stapled, through the corpus oracle in both trust modes (TestCorpus,
  TestOracle), and fetched from the test responder with c2patool's
  `verify.ocsp_fetch` on (TestC2patoolOCSP: all six cases).
- Allowed list (PEM and hash forms) and trust config match c2patool's
  `--allowed_list` / `--trust_config` (TestC2patoolTrustOptions); chains
  match (TestC2patoolChains).
- INTEROP.md: 67 files × 2 modes, 0 unexplained.
- gofmt, build, vet, staticcheck and the full suite are clean. Coverage:
  verify 90.7%, internal/ocsp 77.9%, sign 87.4%, cmd/c2paseal 91.5%,
  root 81.5%.
- Fuzzing, 2 minutes each, no crashers: `FuzzParseResponse` (399k execs),
  `FuzzFile` (6.6k).

**Not done: "a file signed by a certificate on the official trust list
validates as Trusted with that list loaded."** The lists load, but no
publicly licensed JPEG or PNG signed under the conformance program was
found. Checked against the official list with c2patool: `legacy/ocsp.jpg`
(Adobe, 2025), c2pa-c `for_trusted_read.jpg` (c2pa-rs test PKI), c2pa-rs
`adobe_connected_identities.jpg` (Adobe stage) and c2pa-js
`PirateShip_save_credentials_to_cloud.jpg` (Adobe Photoshop, 2026): all
`signingCredential.untrusted` for c2patool too (their TSAs are on the TSA
list). A photo from a conforming product (for example a Pixel 10 or
Galaxy S25 camera image) that may be redistributed would close this; it
needs the user.

**Open issues**
- The fetch path checks the responder's profile but, like c2pa-rs, not its
  trust; it does not log the profile failure c2pa-rs would log for a bad
  responder certificate.

### Phase 21 — Hardening, web UI fixes, release v0.2.0 (2026-11-14)

**Decision (user, 2026-11-14):** start Phase 21 with Phase 20's
trust-list check still open. The user will get a photo from a conforming
device (for example a Pixel 10 camera image that may be redistributed) and
close it later.

**Built**
- Negative fixtures (`scripts/mkbroken`, deterministic: rerunning it
  rewrites the existing files byte for byte): `wrong-hash.jpg`,
  `wrong-hash.png` (1 bit of the hash in `c2pa.hash.data`), `sig-flip.png`,
  `truncated-cabx.png`. PNG edits recompute chunk CRCs, so the only defect
  is the C2PA one. Oracle output was added for the new files only:
  rerunning the oracle on `broken/` changed nothing but the order of
  c2patool's assertion map keys (it prints a hash map), so those files were
  restored. `verify.TestNegativeSet` checks the six classes (tampered
  pixels, bad signature, truncated manifest, expired, wrong hash, revoked
  `ocsp/revoked.jpg`): Invalid with the expected failure in C2paSeal, and
  Invalid or a refusal in c2patool.
- Fuzzing: new `FuzzReadStore`, `FuzzTrustFiles` (root; the trust loaders
  were split into byte-level `parseTrustAnchors`, `parseAllowedList` and
  `parseTrustConfig`, same behaviour) and `verify.FuzzExternalStore`
  (sidecar and remote store, the latter through a stub HTTP client).
  `ParseRequest` was already fuzzed inside `FuzzParseResponse`. Every
  parser added since Phase 13 now has a target.
  `.github/workflows/fuzz.yml`: nightly (02:17 UTC) and by hand. A first
  job finds every `Fuzz*` with grep; then one job per target (5 min, corpus
  cached between nights); crashers are uploaded as
  `crashers-<package>-<target>`.
- Credentio, third external validator:
  - Repo `mediaprovenance.googlesource.com/credentio`, pinned at
    `ee4078badeea5739b0f0f246dbaea7803382718b` (2026-10-15 public release).
    It has a CLI, `tools:c2pa_validate` (`--asset`, `--claim_signer_trust`,
    `--tsa_trust`; crJSON output with the active manifest first).
  - Build confirmed locally in WSL Ubuntu 24.04 with Bazel 9.2.0 (through
    Bazelisk 1.26.0) and LLVM 19.1.7 clang/libc++. WSL here has no sudo and
    no libc headers, so the toolchain was set up in user space: the LLVM
    release tarball, glibc/libgcc/libatomic `.deb`s unpacked into a sysroot,
    clang wrappers, `--host_cxxopt=-stdlib=libc++` for exec tools and an
    rpath for libc++. CI uses the README's route (apt.llvm.org `llvm.sh 19`,
    Bazelisk) and caches the binary with its libc++ libraries behind a
    wrapper script. `-static-libstdc++` does not work: Bazel links with the
    `clang` driver, which ignores it.
  - Harness: `credentioTool` (`$CREDENTIO_VALIDATE` or `c2pa_validate` on
    PATH, `$CREDENTIO_COMMIT`; when not installed it shows
    `$CREDENTIO_BUILD_ERROR`). `explain` now explains each part separately:
    disagreements among C2paSeal, c2patool and c2pa-mcp by the old causes,
    and Credentio's difference from C2paSeal by `credentioCauses`. Each of
    those matches its status pattern and facts from the file's bytes
    (signer EKUs, claim version, store location). Before this, a matching
    c2pa-mcp cause would have hidden any Credentio difference on the same
    row. `WARNING:` lines on stderr are skipped when reporting an error.
  - interop.yml builds Credentio with `continue-on-error`. If the build
    fails, the report shows it as not installed with the reason, and it is
    not in `-require`.
- GitHub Actions: `actions/cache@v6`, `upload-artifact@v7`,
  `download-artifact@v8` (all `node24`, checked in each tag's action.yml;
  release notes read for breaking changes, none affect these workflows).
  checkout@v6 and setup-go@v6 were already node24.
- Web UI (display only; library, CLI and API output unchanged):
  - (a) No store and only `claim.missing` → grey "No Content Credentials"
    badge, a short note, and the status listed neutrally. A remote
    reference that was not fetched (`manifest.inaccessible`) still shows
    Invalid.
  - (b) The drop zone is a `<label>`, inline by default, so its vertical
    padding overlapped the banner above; now `display: block`.
  - (c) `signingCredential.untrusted` (a failure) → amber "warning" with
    "Signer not on your trust list."
  - Found while checking: the per-kind border colours never applied
    (`ul.statuses li` outranked `li.failure`); fixed. Links use the accent
    colour (the dark-mode download link was unreadable).
- Release: CHANGELOG.md (v0.2.0 "unreleased", v0.1.0). `scripts/archive`
  writes tar.gz/zip with sorted entries, every time = SOURCE_DATE_EPOCH
  (default: the commit time), owner 0, fixed modes, no gzip name or time.
  `release.sh` builds with `-trimpath -buildvcs=true`, adds CHANGELOG.md to
  the archives and normalizes SHA256SUMS (Windows `sha256sum` writes `*`).
  `scripts/release-notes.sh` prints the CHANGELOG section plus "Checking a
  release" with the Go version; release.yml publishes with `--notes-file`.
  `.gitattributes`: `* text=auto eol=lf` (with `testdata/** -text` kept
  last), because `core.autocrlf=true` on this machine had checked out
  README, PROGRESS and SPEC with CRLF, and README/LICENSE/CHANGELOG go into
  the archives and `web/index.html` into the binary. Renormalizing changed
  no committed content.
- README: release reproducibility and a CHANGELOG pointer.

**Results**
- Negative set: all 10 files rejected by both tools in trusted mode
  (TestNegativeSet); TestCorpus matches c2patool on the 4 new files in both
  modes.
- INTEROP.md (`-require c2patool,c2pa-mcp,Credentio -strict`, Credentio
  run from the WSL build): 71 files × 2 modes × 4 tools, 142
  disagreements, 0 unexplained. Without Credentio: 77 disagreements, 0
  unexplained. Credentio differs from C2paSeal on every file, for these
  reasons:
  - with no anchors it skips the signer checks (default mode);
  - with anchors it requires the `c2pa-kp-claimSigning` EKU, which neither
    test PKI has, and then reports only `signingCredential.invalid`. C2PA
    2.4 §14.5.1.2 asks only for one EKU the validator has anchors for, and
    §14.4.1 lists emailProtection and documentSigning as configurable;
  - it does not validate 1.x manifests (`com.google.unsupportedSpecVersion`);
  - it reads no sidecar or remote store;
  - it exits with an error on broken containers;
  - it reports a tampered assertion as `assertion.undeclared` (plus
    `claim.hardBindings.missing` when it is the hard binding).
- Web UI checked in a browser: headless Chrome 157 driven over the DevTools
  protocol against `c2paseal serve` (script in the session scratchpad, not
  committed). 16/16 checks in light and dark, at desktop width and 390 px:
  unsigned file through the file input, tampered and trusted files through
  a real `drop` event, the Sign button, and computed colours. Screenshots
  inspected. The same check on the old page measured the drop zone 17 px
  over the banner.
- Reproducible builds: two `release.sh` runs give identical SHA256SUMS;
  archives list owner 0/0, commit-time stamps, and 0755 only on the binary.
  The cross-OS check is in the next entry.
- Fuzzing, no crashers: the three new targets for 2 minutes each
  (FuzzReadStore 11k execs, FuzzTrustFiles 13k, FuzzExternalStore 20k;
  instrumented root and verify packages are slow on Windows), then all 21
  targets for 45 s each, all ok (from 184 execs for FuzzToken to 2.2M for
  jpeg FuzzExtract, run alongside the Bazel build).
- gofmt, build, vet, staticcheck and the full suite are clean. Coverage:
  root 82.8%, verify 90.7%, web 85.9%, png 92.3%.

**Not done here (needs the user)**
- Push, then CI: `ci`, the first nightly `fuzz` run (or start it by hand),
  and `interop` (its Credentio build on GitHub has not run yet).
- Tag `v0.2.0` (gate D: ask first). Set the CHANGELOG date before tagging.
  The release workflow cannot be green until then.

**Open issues**
- Credentio's default mode is not comparable on trust (it skips the
  checks), and its trusted mode stops at the EKU. See Future work
  (claimSigning EKU).
- The browser check script is not in the repo (it needs Node and Chrome).

### Phase 21 — cross-OS reproducibility check (2026-11-14)

Commit d75f81a, cloned fresh on each side (0 changed files), go1.27.1,
`sh scripts/release.sh v0.2.0-repro`: the Windows build (Git Bash) and the
Linux build (WSL Ubuntu 24.04, go1.27.1 linux/amd64 from go.dev) give
identical SHA256SUMS for all six archives (darwin, linux, windows ×
amd64, arm64). The steps in the release notes' "Checking a release" work.

### Phase 21 — first CI runs after push (2026-11-14)

`ci`, `fuzz` (all 21 targets, 5 min each, by hand) and `interop` all
passed on GitHub. But interop's Credentio build had failed inside its
`continue-on-error` step: `ubuntu-latest` is now Ubuntu 26.04 ("resolute"),
and apt.llvm.org has no LLVM 19 repository for it (`llvm.sh 19` stops at
`apt-get update`), so the report showed Credentio as not installed. The
interop job is now pinned to `ubuntu-24.04` (the release the local build
used), and its cache keys name that image instead of `runner.os`, so a
c2patool built on 26.04 is not restored there. Rerun (run 43576518894,
green): Credentio built in 17.5 min (3367 Bazel actions) and was cached
(8 MB); the harness ran it and wrote 71 files, 142 disagreements, 0
unexplained. Its INTEROP.md matches the committed one except for the
per-run values (generation time, manifest UUIDs of the files signed during
the run, their time-stamp times).

### Gate D — approved (2026-11-14)

The user approved v0.2.0 after the gate D report (interop with Credentio
on CI, negative set, fuzz summary). The CHANGELOG date was set in commit
26be9bb (`release v0.2.0`); the tag is pushed by the user.

### Phase 22 — WebAssembly build (2026-11-14)

**Built**
- `cmd/c2paseal-wasm`. `api.go` holds the logic and builds everywhere, so
  its tests run on the host. `main_js.go` (`js && wasm`, `syscall/js` only)
  defines `globalThis.c2paseal`. `main_other.go` gives the package a main
  elsewhere that tells you to build it for js/wasm.
  - `verify(bytes, opts)` returns the JSON of `c2paseal verify --json`
    (`validation_results`, `validation_state`). Options: `trustAnchors`,
    `allowedList`, `trustConfig` (strings) and `manifestStore`
    (Uint8Array).
  - `sign(bytes, opts)` returns the JSON of `c2paseal sign --json` without
    the two file paths, plus `data` (the signed file, base64). Options:
    `cert`, `key`, `title`, `sourceType`, `noHistory` and `ocspResponse`.
  - `version()` returns the JSON of `version --json`.
  - Bad options give `{"error": …}`, as the CLI does with `--json`. A panic
    is turned into such an error rather than stopping the Go runtime for
    later calls.
  - No network in the browser build: no TSA, no remote fetching, no online
    OCSP.
- Library: `ParseSigner`, `ParseTrustAnchors`, `ParseAllowedList` and
  `ParseTrustConfig`, the `Load*` functions on bytes (the browser has no
  paths). `LoadSigner` now calls the same parser, and its errors still
  name the file (tested).
- Size budget: `WasmBudget` = 4 MiB gzipped (`gzip.BestCompression`), in
  `TestWasmSize`, which runs in every `go test ./...` (it builds the
  `.wasm` with the release flags `-trimpath -ldflags=-s -w`). At this
  phase: 14.48 MB raw, 3.74 MB gzipped with Go's gzip (3.70 MB with
  `gzip -9`), 89% of the budget. TinyGo was not needed; it stays the option
  if the standard build outgrows the budget. It would be a new toolchain,
  ask first.
- Browser test: `TestBrowser` (runs with `C2PASEAL_BROWSER_TEST=1`). No
  browser test tool was added. The test serves `testdata/browser.html`,
  `wasm_exec.js` from the same Go, the `.wasm` and the fixtures from an
  `httptest` server, starts headless Chrome (`$C2PASEAL_CHROME` or a usual
  install path), and reads the results that the page POSTs back.
  - 13 cases: verify signed JPEG (default and trusted), signed PNG and
    time-stamped JPEG (trusted), tampered JPEG and PNG, unsigned PNG; sign
    an unsigned JPEG and PNG and re-sign a signed JPEG (2 manifests); and
    three error cases.
  - The verify cases must equal this process's `verify()` JSON byte for
    byte. Each signed file is verified again in the browser and must match
    the host's JSON for the same bytes, and verify as Trusted on the host.
- CI: a new `wasm` job in ci.yml (ubuntu-24.04, whose image has Chrome).
  It builds the `.wasm` once, writes its size to the step summary, runs vet
  and staticcheck for js/wasm, runs `TestWasmSize` and `TestBrowser` on
  that file, and uploads `c2paseal.wasm` with `wasm_exec.js` as an
  artefact.
- README ("In the browser") and CHANGELOG (Unreleased).

**Results (local, Windows, Chrome 157 headless)**
- TestBrowser 13/13 and TestWasmSize pass. No Chrome processes or profile
  folders are left behind.
- Mutation check: a page that drops the verify options fails exactly the 6
  cases that depend on them.
- gofmt, build, vet and staticcheck (host and js/wasm) and the full suite
  are clean. Coverage: root 83.6%, cmd/c2paseal-wasm 85.4% (host tests
  only; the `syscall/js` glue is covered by TestBrowser).

**Not done here (needs the user)**
- Push, and the `wasm` CI job must be green: that is the phase's "Done
  when".

**Open issues**
- Phase 23's raw manifest view needs the manifest store, which `verify()`
  does not return. Add an `inspect(bytes)` (the JSON of `inspect`) in
  Phase 23, where it is used.
- The `.wasm` is not in the release archives yet; Phase 23 deploys it with
  the site.

### Phase 22 — CI result (2026-11-14)

Pushed with the v0.2.0 tag. ci run 43581089917 passed on GitHub, including
the new `wasm` job: c2paseal.wasm was 14,508,672 bytes, 3,712,574 gzipped
(`gzip -9`, 3,751,578 with Go's gzip, 89% of the budget), and TestBrowser
passed 13/13 in Chrome 157 on Linux. Phase 22 is done. The release run
43581110817 passed, and v0.2.0 is published with 7 assets.

### Phase 23 — Static web app on GitHub Pages (2026-11-14)

**Built**
- `web/site/`, the static app: `index.html`, `app.js`, `app.css`, `sw.js`,
  `icon.svg`, plus `demo/` (byte-exact copies of the TEST ONLY chain, key
  and root, and `testdata/unsigned/large.jpg` as the sample).
  - Tabs: "Verify a file" (drag-and-drop or file picker, an option to also
    trust the demo root) and "Sign a sample" (the sample or your own file,
    plus "Sign the signed file again" to show the edit history).
  - Status banner, chosen from the library's statuses and state only:
    - valid ("Valid, trusted signer" or "Valid");
    - signer not on your trust list (Valid with
      `signingCredential.untrusted`);
    - "Changed since it was signed" (Invalid with a data hash, hashed URI
      or claim signature mismatch on the active manifest);
    - "Content Credentials not valid" (any other Invalid);
    - "No Content Credentials" (the Phase 21 rule).
  - Wording as in the spec: "Signed by X (certificate issued by Y),
    unmodified since <time-stamp time>". Without a time-stamp it says the
    time is not known. The test fails if the visible text says real, true,
    genuine, authentic or fake.
  - Provenance graph: manifest cards, with ingredients hanging below them
    (`activeManifest` / `c2pa_manifest` links, so v1 files work too).
    Ingredients without a manifest are leaves.
  - Raw manifest store (pretty JSON) and the status list, collapsible.
  - Kept from Phase 21: the drop zone is a block, the per-kind status
    colours, the untrusted signer shown as a warning, links in the accent
    colour.
  - The CSP is in a meta tag (Pages cannot send headers) and in serve's
    header. It is `script-src 'self' 'wasm-unsafe-eval'`, with no inline
    script or style. A test checks that the two are the same.
- Engines (`app.js`): if `c2paseal.wasm` is there, it is loaded and
  `globalThis.c2paseal.analyze/sign` are used. Otherwise (under `serve`)
  `api/verify` and `api/sign` are used. Both return the JSON of the new
  `internal/analysis` package (moved out of `web`, without net/http). The
  WebAssembly build gained `analyze(bytes, {name, trustAnchors})`; a test
  checks that it gives the same JSON.
- Offline: `sw.js` caches every app file, including the `.wasm`, and
  serves from the cache first. app.js registers it only with the
  WebAssembly engine. The pages workflow replaces its VERSION with the
  commit, so each deployment gets a new cache and drops the old one. A test
  checks that the ASSETS list and the site's files match.
- `serve` embeds the same site (`web.Site()`, `http.FileServerFS`). The
  `web` types are now aliases of `internal/analysis`, so the package API is
  unchanged except for the new `Site` and `ContentSecurityPolicy`.
  `.gitattributes` keeps `web/site/demo/**` byte-exact; `TestDemoPKI`
  compares those files with `testdata`.
- `TestSite` (cmd/c2paseal-wasm, `C2PASEAL_BROWSER_TEST=1`). A test page
  loads the real app in an iframe at `/app/` (a subpath, as on Pages) and
  drives it:
  - 8 dropped files (untrusted, trusted PNG, time-stamped, tampered JPEG
    and PNG, expired signer, no credentials, the 1.x edit history CACA.jpg)
    with the expected banner, text and graph;
  - the Sign tab: sign the sample, then sign it again (1, then 2
    manifests). The downloaded files are checked in Go: Trusted under the
    demo root;
  - offline: once the service worker controls the app, the server answers
    503 for `/app/`, the app is reloaded, and a verify and a sign must
    still work. No app request may reach the server.
  - The same page and checks also run against `web.Handler`, which proves
    the serve fallback.
- CI: the `wasm` job also runs TestSite. New `pages.yml` (push to main, or
  by hand) runs the browser tests, assembles `_site` (site, `.wasm`,
  `wasm_exec.js`, stamped `sw.js`), writes the sizes to the step summary,
  and deploys with `configure-pages@v6`, `upload-pages-artifact@v5` and
  `deploy-pages@v5`, all checked to run on node24 or composite.
- README: the site link, and how serve and Pages share the site.
  CHANGELOG: under Unreleased.

**Results (local)**
- TestSite passes in both engines, 8 times in a row. The first version was
  flaky: "Sign the sample" fetched the sample before registering the
  operation, so `whenIdle()` could resolve early. Fixed in app.js, where it
  was a real ordering bug in the test hook.
- Mutation check: a service worker that always goes to the network fails
  the offline test.
- Screenshots (scratchpad script over the DevTools protocol, site served
  under `/c2paseal/`): every state in light and dark, at 1100 px and 390 px,
  inspected. No horizontal overflow, no console errors or warnings.
  - With Chrome's network emulation set to offline, a reload loads the app
    from the service worker and verifies a file.
  - Fixed after looking: the Sign tab said "drop your own file on the
    button", but it is a file picker.
- Sizes: c2paseal.wasm 14.54 MB, 3.76 MB gzipped with Go's gzip (90% of
  the budget; `analyze` added about 12 KB). The rest of the site is 187 KB
  (the sample image is 157 KB).
- gofmt, build, vet and staticcheck (host and js/wasm) and the full suite
  are clean. Coverage: web 84.8%, internal/analysis 88.2%,
  cmd/c2paseal-wasm 87.2%.

**Not done here (needs the user)**
- Turn on Pages with "GitHub Actions" as the source, then push. The site
  must be live, and work offline, at
  https://nyasa-parikh-17.github.io/c2paseal/.
- Gate E: report the URL, the browser check and the size, then ask before
  tagging `v0.3.0` (set the CHANGELOG date first).

**Open issues**
- The app trusts only the demo root (or nothing). Choosing your own trust
  list file, such as the official C2PA list, is in Future work. Without it,
  files from real cameras show "Signer not on your trust list".
- Whether Pages compresses `.wasm` will be known after the first deploy.

### Phase 23 — first deploy (2026-11-14)

- The user turned on Pages (source: GitHub Actions) and pushed c1efc22.
  `pages` run 43585541679 passed: the site is live at
  https://nyasa-parikh-17.github.io/c2paseal/ (sw.js VERSION
  `c1efc22ca14d`).
- Pages gzips everything: c2paseal.wasm is sent as `application/wasm`,
  3,869,555 bytes on the wire.
- Live check (the scratchpad DevTools script, pointed at the Pages URL):
  - All states as expected; sign, and sign again, work.
  - The service worker controls the page. With Chrome's network emulation
    set to offline, a reload loads the app and verifies a file.
  - No console errors.
- ci run 43585541708 failed on windows-latest only: TestPageAndErrors got
  `application/javascript` for .js. net/http takes types from the Windows
  registry. The site's file types are now fixed in `web.siteTypes`, so
  serve sends the same types on every OS; the test was not loosened.

### Gate E — approved (2026-11-14)

ci (all four jobs, Windows included) and pages are green on 782c110. The
user approved v0.3.0; the CHANGELOG date was set in the `release v0.3.0`
commit, and the tag is pushed by the user. Phase 23 is complete once the
release workflow is green.

### Phase 24 — Pluggable key providers (2026-11-14)

**Decision (user, 2026-11-14):** use the official SDKs for the KMS
providers (aws-sdk-go-v2; cloud.google.com/go/kms), each only in its own
module.

**Built**
- `sign.KeyProvider` (`Open(ctx, *url.URL) (crypto.Signer, error)`),
  `sign.RegisterKeyProvider` (case-insensitive scheme; panics on a
  duplicate or nil, like `database/sql.Register`), `sign.OpenKey` and
  `sign.KeySchemes`.
  - `file:` is built in: `file:rel/key.pem`, `file:///abs/key.pem`,
    `file://localhost/…`, escaped paths, and Windows `file:///C:/…`. A plain
    path or a Windows drive path is a file too.
  - An unregistered `awskms:`/`gcpkms:` names the module to import. Errors
    redact the URI's user info and query.
  - `sign.ParsePrivateKey` now holds the PEM key parsing, which the root
    package uses too. Added `c2paseal.LoadChain`.
  - The CLI's `sign --key` takes a path or a key URI (tested with `file:`,
    and with `awskms:` for the error that names keys/awskms).
- `sign/signtest`, in the core module with no new dependencies:
  - `Chain(t, pub)` issues a leaf for any public key under the TEST ONLY
    intermediate, with the leaf.pem profile;
  - `Check(t, signer, chain)` signs `unsigned/small.jpg` and `small.png`
    and requires Valid/Trusted in C2paSeal and in c2patool
    (`C2PASEAL_REQUIRE_C2PATOOL=1` makes a missing c2patool fatal).
  - Its own test is the baseline, with an in-memory key: c2patool says
    Valid and Trusted.
- `keys/awskms` (module; aws-sdk-go-v2 v1.48.0, config v1.33.18,
  service/kms v1.62.6):
  - `awskms:<ARN | key ID | alias/… | alias ARN>[?region][&profile][&endpoint]`;
    the region comes from the ARN when it is not given.
  - `New` checks ECC_NIST_P256, SIGN_VERIFY, ECDSA_SHA_256 and a P-256
    SPKI. `Sign` sends the digest (MessageType DIGEST) and verifies the
    returned DER signature locally before using it.
  - It accepts nil `SignerOpts`, because go-cose passes nil (found by the
    first test run).
- `keys/gcpkms` (module; cloud.google.com/go/kms v1.37.0 REST client):
  - `gcpkms:<key version name>[?endpoint]`. An `http://` endpoint gets
    `WithoutAuthentication`, so tokens are never sent in the clear.
  - `New` checks EC_SIGN_P256_SHA256, the PEM's CRC32C and the response
    name. `Sign` sends the digest with its CRC32C and checks
    verifiedDigestCrc32c, the signature's CRC32C, the name and the
    signature itself. `Signer.Close` closes the client.
- Both modules have `replace github.com/Nyasa-Parikh-17/c2paseal => ../..`
  (and require v0.0.0) until the core module is tagged with this API; see
  Open issues.
- Fake KMS endpoints (httptest) in each module's tests:
  - AWS: JSON 1.1 with `X-Amz-Target`; the test also checks that every
    request is SigV4-signed for `eu-west-1/kms` with the test credentials,
    and keeps the SDK away from this machine's credentials and config.
  - GCP: REST with the SDK's own protobuf types; the test checks that no
    Authorization header reaches the http:// fake.
  - Knobs cover a wrong key spec or algorithm, wrong usage, an RSA public
    key, unknown keys, bad checksums, a wrong response name, a signature
    from another key, a short digest, the wrong hash, and KMS being down.
  - `TestRealKMS` in each module runs only with
    `C2PASEAL_AWSKMS_KEY`/`C2PASEAL_GCPKMS_KEY` and credentials. The
    certificate is issued on the fly, so only the key is needed.
- CI:
  - The `test` job checks that the core module's direct dependencies are
    exactly the three allowed (CLAUDE.md rule 2).
  - A new `keys` job (matrix awskms, gcpkms) installs c2patool (cached
    under the interop job's key), runs vet and staticcheck, and runs the
    tests with c2patool required. The real-KMS tests are wired to optional
    repository secrets (`C2PASEAL_AWSKMS_KEY`,
    `C2PASEAL_AWS_ACCESS_KEY_ID`, `C2PASEAL_AWS_SECRET_ACCESS_KEY`,
    `C2PASEAL_GCPKMS_KEY`, `C2PASEAL_GCP_CREDENTIALS`).
- Docs: README "Keys in a KMS", a README in each module, CHANGELOG
  (Unreleased).

**Results (local)**
- Files signed through each provider (fake KMS): c2patool says Valid
  (default trust) and Trusted (TEST ONLY root), for JPEG and PNG. The same
  holds in C2paSeal.
- The core `go.mod`/`go.sum` are unchanged (git), and the direct
  dependencies are still digitorus/timestamp, fxamacker/cbor and
  veraison/go-cose.
- gofmt, vet and staticcheck are clean in all three modules, and the full
  core suite passes. Coverage: sign 88.5%, sign/signtest 72.3%, root 82.8%,
  keys/awskms 96.6%, keys/gcpkms 92.1%.
- The wasm build is unchanged in practice: 3.76 MB gzipped, 90% of the
  budget.

**Not done here (needs the user)**
- Push. The `keys` CI job must be green.
- A real KMS signs in CI only if the user adds the secrets above.

**Open issues**
- Until the core module is tagged with `sign.KeyProvider` (v0.4.0, Phase
  25), the key modules build only inside this repository (`replace ../..`).
  At v0.4.0: set their `require` to v0.4.0, drop the `replace`, and tag
  `keys/awskms/v0.4.0` and `keys/gcpkms/v0.4.0` as well.
- The `c2paseal` CLI cannot open KMS keys: it is in the core module, and
  importing the providers would add their SDKs to it. sealsvc (Phase 25)
  will need a way to use them; decide its module layout there.

### Phase 23 and 24 — CI results (2026-11-14)

- v0.3.0: release run 43589471955 passed; published with 7 assets. Phase 23
  is done.
- Phase 24: ci run 43589468831 passed, all six jobs. In both `keys` jobs,
  c2patool 0.27.21 (restored from the interop cache) said Valid/Trusted for
  the files signed through the fake KMS; TestRealKMS skipped (no secrets).
  Phase 24 is done.

### Phase 25 — sealsvc signing server (2026-11-14)

The user asked for Phases 25 and 26 together. Phase 25 ends at gate F, so
Phase 26 waits for approval there.

**Built**
- `cmd/sealsvc`, its own module: it imports the core module plus
  keys/awskms and keys/gcpkms (with `replace` until v0.4.0), so it can open
  KMS keys while the core `go.mod` stays unchanged. This settles the
  Phase 24 open issue about the module layout.
- API:
  - `POST /v1/sign`: raw JPEG/PNG body; answers with the signed file and
    the `C2paseal-Active-Manifest` and `C2paseal-Manifests` headers. Query
    parameters: `title`, `source_type`, `no_history`.
  - `POST /v1/verify`: JSON as `c2paseal verify --json`.
  - `GET /healthz` and `GET /metrics`, with no key.
  - Errors are JSON with a `request_id`, which also goes in `X-Request-Id`.
  - Status codes: 400, 401 (with `WWW-Authenticate`), 403, 413, 415, 422,
    429 and 503 (both with `Retry-After`), and 502 for key or TSA failures.
  - Failures are classified by cause, not by message: each request wraps
    the signer, so a KMS error (502) is told apart from a bad file (422).
- API keys:
  - The file has `<name> <sha256> [rate=] [scopes=]` per line. Lookup
    hashes the bearer token and compares it with every entry in constant
    time.
  - `sealsvc hash-key` prints a fresh 32-byte key and its line for the
    file.
  - Per-key token bucket (burst = the per-minute rate) and a global
    concurrency limit (503).
  - `MaxBytesReader` for the body; header, read, write and idle timeouts;
    `MaxHeaderBytes`.
- Audit log: `log/slog` JSON, one record per sign or verify request, plus
  start and stop records.
  - Fields: request ID, endpoint, method, path, remote address, status,
    sizes, duration, API key name, forwarded_for and user agent (both
    logged only), and for signing the format, the input and output SHA-256,
    the active manifest and the number of manifests (the validation state
    for verify).
  - A test checks that no key, hash or "Bearer" appears in the log.
  - The start record redacts the key URI's query.
- Metrics, Prometheus text 0.0.4 written with the standard library:
  build_info, requests_total{endpoint,code}, a request duration histogram,
  request/response bytes, signatures_total{key}, rate_limited_total{key},
  auth_failures_total, busy_total and in_flight_requests. Output order is
  stable. A test checks every line against the sample grammar.
- `sealsvc healthcheck` (distroless has no curl) and `version`. Flags have
  SEALSVC_* environment equivalents. At startup it refuses a key that does
  not match the certificate. Optional TLS (minimum 1.2).
- Container:
  - `cmd/sealsvc/Dockerfile`: multi-stage, `--platform=$BUILDPLATFORM`
    with cross-compiled GOOS/GOARCH, CGO_ENABLED=0, `-trimpath`, the
    version through `-X main.version`; final image
    distroless/static-debian12:nonroot with HEALTHCHECK.
  - `.dockerignore` keeps the build context to sources.
  - `deploy/sealsvc/compose.yaml`: read-only, cap_drop ALL,
    no-new-privileges, port bound to 127.0.0.1, healthcheck.
- CI:
  - A new `sealsvc` job: vet, staticcheck and tests (c2patool required).
    It then builds the image and runs it read-only with `--cap-drop ALL`
    and the TEST ONLY key: healthz, sign with curl, c2patool says Trusted,
    verify says Trusted, a request without a key gets 401, `docker exec …
    healthcheck` works, and the image user is nonroot. The image size goes
    in the step summary.
  - Release: the test job also tests the three extra modules. A new `image`
    job (QEMU, buildx, GHCR login with GITHUB_TOKEN, `packages: write`)
    pushes linux/amd64 and linux/arm64 tagged `v0.4.0`, `0.4.0` and `0.4`.
    The docker/* actions run on node24.
- Refactors for the tests: `signtest.CheckFile` (Check uses it), and the
  fake AWS KMS moved to an exported `keys/awskms/awskmstest` package that
  the awskms tests and sealsvc use.
- Docs: `cmd/sealsvc/README.md` (API, configuration, audit log sample,
  security notes), a README section, CHANGELOG (Unreleased).

**Results (local)**
- TestKMSEndToEnd, the phase's check: `run()` starts the real server with
  an `awskms:` URI pointing at the fake KMS (the certificate is issued for
  the fake's key) and an audit file. A JPEG and a PNG are signed over HTTP.
  c2patool says Valid (default) and Trusted (TEST ONLY root) for both, and
  /v1/verify says Trusted. KMS calls: 1 GetPublicKey, 2 Sign. A clean
  shutdown writes the stop record.
- Also tested: auth (401 and 403), size (413), empty body, not an image,
  bad parameter, 422 for a broken JPEG and for a source type on a signed
  file, rate limit (429 with Retry-After 31 on a fake clock, other keys
  unaffected), busy (503), a signer failure (502 with "signing failed", the
  details only in the log), metrics, the audit log, key file parsing, the
  token bucket, subcommands and startup configuration errors.
- gofmt, vet and staticcheck are clean in all four modules, and all suites
  pass. Coverage: sealsvc 93.3%. The core `go.mod` is unchanged; its direct
  dependencies are the three allowed.
- Not checked locally: the Docker image (Docker is not running on this
  machine). The `sealsvc` CI job builds and runs it on every push.

**Not done here (needs the user)**
- Push. The `sealsvc` job (tests plus the image) must be green.
- Gate F: report the API, the security notes and an audit log sample, then
  ask before tagging v0.4.0. The image is published by the release
  workflow. At v0.4.0 also: point the key modules and sealsvc at the
  tagged core module (drop the `replace` lines) and tag
  `keys/awskms/v0.4.0`, `keys/gcpkms/v0.4.0` and `cmd/sealsvc/v0.4.0` (see
  the Phase 24 open issue).
- GHCR packages start private; after the first push the package may need
  to be made public in the repository's package settings.

### Phase 25 — first CI run (2026-11-14)

ci run 43595167389: every job passed except `sealsvc`, whose
TestMetricsAndHealth rejected `…_sum{endpoint="verify"} 1.6244e-05`. That
is a valid sample: the test's grammar had no `-` in the exponent, and on
Windows the durations round to 0, so it never showed locally. The pattern
now follows Go's float format (and NaN/±Inf), and a new TestSampleGrammar
pins it. The image steps had not run (they come after the tests).

### Phase 25 — CI green (2026-11-14)

ci run 43598198487 passed, all seven jobs. In the `sealsvc` job:
- The tests: c2patool says Valid/Trusted for files signed through the
  server, including through the fake AWS KMS (TestKMSEndToEnd). This is the
  phase's CI check.
- The image ran read-only with `--cap-drop ALL`: healthz ok; signed over
  HTTP with curl; c2patool `validation_state == "Trusted"` (true);
  /v1/verify Trusted (true); a request without a key got 401;
  `docker exec … healthcheck` printed ok; the user is nonroot. The start and
  sign audit records are in the container log.

Phase 25 now waits at gate F: v0.4.0 needs the user's approval.

### Gate F — approved (2026-11-14)

The user approved v0.4.0. The CHANGELOG date is set in the `release v0.4.0`
commit; the user pushes the tag. After the tag: point keys/awskms,
keys/gcpkms and cmd/sealsvc at core v0.4.0, drop the `replace` lines, and
tag the three modules.

### Phase 26 — WebP (2026-11-14)

The user approved gate F ("yes, this is version 4") and asked to continue
with Phase 26.

**What c2pa-rs does** (read from `sdk/src/asset_handlers/riff_io.rs` at tag
c2pa-v0.90.21, the version under c2patool 0.27.21):
- The store is the data of a top-level `C2PA` chunk. Any existing one is
  removed and the new one appended last in the RIFF.
- VP8X is not changed for C2PA; only adding XMP sets its XMP flag (4),
  creating a VP8X from the VP8 or VP8L size when there is none.
- The hash exclusion is the chunk offset with length 8 + data length: the
  pad byte after odd data is hashed. The oracle fixtures confirm it:
  `small.webp` has a 17867-byte store, excluded as start 86, length 17875.

**Built**
- `container/webp` (standard library only):
  - `Chunks` checks every chunk against the RIFF size; a missing pad byte at
    the very end is accepted, as libwebp does.
  - `Extract`, `Strip` and `Insert` (appends last, updates the RIFF size,
    restores a missing final pad byte, keeps any bytes after the RIFF), and
    `WriteStore`.
  - `Chunk.ExclusionLength`.
  - `XMP` and `SetXMP`: replaces an existing XMP chunk in place, or adds one
    before the C2PA chunk; sets the VP8X XMP flag, or builds a VP8X from
    the VP8L or VP8 header. Unlike c2pa-rs, it also sets the alpha flag when
    VP8L says alpha is used, as the container specification requires.
- Wired through: `internal/asset` (Detect, Extract, XMP, SetXMP),
  `sign.Asset` (a `webpContainer` whose exclusion is ExclusionLength),
  `c2paseal.FormatWebP`, the CLI's folder walk (`.webp`), the interop
  container facts, the web app (accept, drop text, download MIME), sealsvc
  (415 check, `image/webp`), and doc comments.
- Fixtures (`scripts/make-webp-fixtures.sh`, which leaves the rest of the
  corpus alone):
  - unsigned: small (VP8L), lossy (VP8), alpha (VP8X+ALPH+VP8) and large,
    made with Pillow 10.4 / libwebp 1.4.0 from the existing PNG originals;
    the output is deterministic (regenerated byte for byte).
  - signed by c2patool: small and ts with the automatic thumbnail;
    lossy, alpha and large without (c2patool's WebP thumbnail of a lossy
    64×48 source is about 311 KB and stored twice, so large.webp came out
    at 3.3 MB). c2patool adds the source as a `parentOf` ingredient for
    WebP; that is in the oracle output.
  - broken (scripts/mkbroken, which still rewrites the old files byte for
    byte): data-flip, sig-flip, wrong-hash, truncated-c2pa.
  - Oracle output for the new files only: `scripts/oracle -only '*.webp'`
    (new flag). No existing oracle file changed.
- Tests:
  - The corpus tests now include WebP: 78 WebP cases in TestCorpus. Two test
    helpers that assumed "PNG or JPEG" now use `asset.Extract`. The manifest
    test's thumbnail check accepts `image/webp`; the oracle does not record
    the format, so that was the test's own assumption.
  - `container/webp` (93.8%): the oracle exclusion equals ExclusionLength
    on every signed fixture, the chunk is last, Insert(Strip(f)) == f; odd
    and even stores, an unpadded last chunk, trailing bytes, errors; SetXMP
    on all three layouts, flags and the 64×48 size, replacement.
  - Signing (root): each layout signed by C2paSeal, and the c2patool-signed
    small.webp re-signed (2 manifests), all Valid/Trusted in c2patool. Every
    one had an odd store (pad byte after the exclusion), so
    TestSignWebPEvenStore varies the title until the store is even; c2patool
    accepts that too.
  - Remote signing writes the XMP chunk with VP8X flagged.
  - TestNegativeSet has the four WebP defects; sealsvc signs WebP (c2patool
    Valid/Trusted); TestSite has a trusted and a tampered WebP in both
    engines.
- Fuzz targets `FuzzStripInsert` and `FuzzXMP` (container/webp): 45 s and
  30 s locally, about 250k and 370k execs, no crashers. The nightly fuzz
  workflow finds them by grep.
- Interop: the harness picks up the WebP fixtures and signs the unsigned
  ones five ways. The truncated-container causes now cover the RIFF wording
  (c2patool `could not be parsed`, Credentio `RIFF chunk extends beyond the
  end of the file`), and the base cause's text names all three containers.
  INTEROP.md: 104 files × 2 modes × 4 tools, 208 disagreements, 0
  unexplained. On every WebP row C2paSeal and c2patool give the same state,
  including C2paSeal-signed files with a time-stamp, a parent, a sidecar and
  a remote store.
- Docs: README (formats, scope, limits), testdata/README (kept CRLF; it is
  `-text`), CHANGELOG (Unreleased).

**Results**
- Done-when: WebP files pass the same checks as JPEG and PNG, including
  c2patool: the oracle corpus, signing, the negative set, interop, the web
  app and sealsvc.
- gofmt, vet and staticcheck are clean (host and js/wasm) and every suite
  passes in all four modules. The wasm build is 3.77 MB gzipped (90% of the
  budget).

**Open issues**
- `.wasm` budget headroom is down to about 10%; HEIC/AVIF (Phase 27) will
  add code. Look at what grows before raising it.
