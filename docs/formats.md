# Formats and scope

C2paSeal targets the C2PA 2.4 specification (pinned in
[SPEC.md](../SPEC.md)). Results are compared with c2patool 0.27.21, built
on the C2PA reference implementation.

## Image formats

| Format | Where the manifest goes | Hard binding | Read | Verify | Sign |
|---|---|---|---|---|---|
| JPEG | APP11 segments (JPEG XT boxes) | `c2pa.hash.data` | ✓ | ✓ | ✓ |
| PNG | `caBX` chunk | `c2pa.hash.data` | ✓ | ✓ | ✓ |
| WebP | RIFF `C2PA` chunk | `c2pa.hash.data` | ✓ | ✓ | ✓ |
| HEIC / HEIF | ISO BMFF `uuid` box | `c2pa.hash.bmff.v3` (v2 and v1 verified too) | ✓ | ✓ | ✓ |
| AVIF | ISO BMFF `uuid` box | `c2pa.hash.bmff.v3` | ✓ | ✓ | ✓ |

Video (MP4, MOV) is planned next; PDF is not scheduled. See the
[project status](project.md).

## Manifests

| | |
|---|---|
| Claims | Writes claim v2. Reads v2 and C2PA 1.x claim v1 |
| Signatures | Signs ES256. Verifies ES256, ES384, ES512, PS256, PS384, PS512, Ed25519 |
| Assertions written | `c2pa.actions.v2`, the hard binding, `c2pa.ingredient.v3` (the parent, when re-signing), optional `c2pa.thumbnail.claim`, `c2pa.soft-binding` |
| History | Re-signing keeps earlier manifests byte for byte and records the previous one as the parent ingredient |
| Location | Embedded, a `.c2pa` sidecar, or a remote URL referenced from XMP (JPEG, PNG, WebP) |
| Time-stamps | RFC 3161 `sigTst2` (and 1.x `sigTst`), verified when present, optional when signing |
| Trust | PEM trust lists, allowed lists and extra EKUs, as c2patool |
| Revocation | OCSP for the signer: stapled, fetched, or stapled when signing |

## Known limits

- **HEIC and AVIF:** no remote manifest references (no XMP written into
  ISO BMFF files yet), no update manifests, no Merkle hashes for
  fragmented files.
- **Signing writes the parent ingredient only:** no component
  ingredients, no ingredient thumbnails, no auto-generated thumbnails.
- **Revocation:** no CRLs, no checks of time-stamp authorities or
  intermediates.
- **C2PA 1.x** files are read and verified, not written. Stores from before
  C2PA 1.0 are refused, as c2patool refuses them.
- **Sidecars** are `<name>.c2pa`, so `photo.jpg` and `photo.png` in one
  folder would share a sidecar path.
- **A time-stamped file** reserves about 10 KiB for the token, whatever its
  real size.

## How it is checked

- **The oracle:** every fixture has c2patool's output next to it, and the
  tests compare C2paSeal's results with it. Those files are generated,
  never hand-edited.
- **Interop:** [INTEROP.md](../INTEROP.md) runs 122 files through
  C2paSeal, c2patool, c2pa-mcp and Credentio, and explains every
  disagreement.
- **Fuzzing:** every container parser and decoder has a fuzz target,
  run nightly.
- **Bad input never panics.** A malformed file becomes failure status
  codes, not a crash or a Go error.
