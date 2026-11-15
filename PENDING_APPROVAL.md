# Image features awaiting approval

Everything the agreed phases list for images (Phases 0–31) is built. This
file lists image work that is **not approved**: each item needs a yes before
it is scheduled as a phase.

Each entry says what it is, why it matters, roughly how big it is, and what
it would cost. Sizes: **S** about one phase or less, **M** one to two
phases, **L** several phases or open research.

Longer-term and non-image ideas are in [FUTURE_SCOPE.md](FUTURE_SCOPE.md).
Video (Phases 32–33) is already approved and is not listed here.

## One open check (needs a file, not a decision)

**Phase 20: a real camera photo against the official trust list.** Phase
20 is done except one check: verifying a photo signed by a C2PA-conforming
camera or phone against the official C2PA trust list. It needs an original
file from such a device (copied directly, not sent through a chat app,
which strips the credentials). The photo provided on 2026-11-16 had been
re-encoded and carried no credentials, so it could not be used.

## Verification

| # | Item | Why | Size | Cost / risk |
|---|---|---|---|---|
| V1 | **Full actions rules**: rules that need ingredient relationships (`c2pa.opened` → one `parentOf`, `c2pa.placed` → `componentOf`), `c2pa.translated` languages, metadata and redaction rules | Files that break these rules currently pass. c2patool checks some of them | M | More oracle fixtures |
| V2 | **Redacted ingredients**: the claim-signature fallback when a redaction breaks an ingredient manifest's hash | Correct results for redacted files | S | Needs real redacted fixtures |
| V3 | **C2PA 1.x verifiable credentials** (`c2pa.credentials`) checked, not only shown; strict v1 validation | Older files verified fully | S | 1.x is legacy; low demand |
| V4 | **More revocation**: CRLs, OCSP for time-stamp authorities and intermediates, the `c2pa.certificate-status` assertion | Revoked intermediates and TSAs are not detected today | M | Network access when verifying; more PKI fixtures |
| V5 | **Remote manifest discovery** through the HTTP `Link: rel=c2pa-manifest` header; extended XMP for packets over 64 KB in JPEG | Some published files are only findable this way | S | — |

## Signing

| # | Item | Why | Size | Cost / risk |
|---|---|---|---|---|
| S1 | **Signing algorithms beyond ES256**: ES384, ES512, PS256, Ed25519 | Some CAs and KMS keys use them; verifying them is already supported | S | More oracle fixtures |
| S2 | **Component ingredients**: `componentOf`, `c2pa.placed` and `c2pa.removed`; ingredient thumbnails | Composites (a photo placed into a layout) can record their sources | M | API design for passing ingredients in |
| S3 | **Auto-generated thumbnails** | Validators and viewers show a preview from the manifest | M | Decoding and resizing images. The standard library covers JPEG and PNG; WebP, HEIC and AVIF would need a dependency, which hard rule 2 does not allow in the core module |
| S4 | **Re-signing a file whose only store is a sidecar or remote** | Today the parent ingredient must be embedded | S | — |
| S5 | **XMP in ISO BMFF**, so HEIC and AVIF can carry a remote manifest reference | Parity with JPEG, PNG and WebP | S | Byte-exact XMP box writing |
| S6 | **BMFF update manifests** ("original"/"update" purposes) | Update manifests for HEIC and AVIF | M | Rarely seen in the wild |
| S7 | **New test PKI with the `c2pa-kp-claimSigning` EKU** | C2PA 2.4 recommends it. Credentio trusts only that EKU, so in trusted mode it stops early on every test file | M | New keys, and every fixture and oracle file regenerated: a large, mechanical change |

## More image formats (new; not in any phase)

The C2PA specification defines manifest embedding for more image formats
than C2paSeal supports. Candidates, each a container reader and writer, a
hard binding, fuzz targets, oracle fixtures and interop rows:

| # | Format | Size | Note |
|---|---|---|---|
| F1 | **TIFF and DNG** | M | Camera raw files; IFD offsets must be patched when inserting |
| F2 | **GIF** | S | |
| F3 | **SVG** | S | XML; exclusion ranges in text |
| F4 | **JPEG XL** | M | Check c2patool's support first; without the oracle there is nothing to check against |

Check [SPEC.md](SPEC.md)'s pinned revision and c2patool's support before
scheduling any of these.

## Watermark and recovery

| # | Item | Why | Size | Cost / risk |
|---|---|---|---|---|
| W1 | **Crop-robust watermark**: a synchronisation template, or a search over crop offsets | Today any crop, even 2 %, loses the mark ([ROBUSTNESS.md](watermark/ROBUSTNESS.md)) | L | Research; slower extraction; may lower invisibility |
| W2 | **Keyed watermark**, readable only with a key | Stops anyone else from reading or forging the mark | M | Key management for the store and the readers |
| W3 | **C2PA Soft Binding Resolution API** in `sealstore` | Other C2PA tools could look manifests up in sealstore | M | Follow the spec's API exactly; more endpoints to secure |
| W4 | **Recovery in `c2paseal serve`** | The local web app's Recover tab works (today: only the Pages build) | S | Needs the watermark in the core module, which brings `golang.org/x/image`. Requires changing hard rule 2 |

## Web app

| # | Item | Why | Size | Cost / risk |
|---|---|---|---|---|
| A1 | **Load your own trust list in the browser** (for example the official C2PA list) and keep it between visits | Today the app trusts the demo root or nothing, so real files show "signer not on your trust list" | S | — |

## How to approve

Say which items, for example "approve S1 and A1". Each approved item gets
its own phase in PHASES.md, with a "Done when" check, before work starts.
