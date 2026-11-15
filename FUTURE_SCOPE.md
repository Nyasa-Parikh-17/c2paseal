# Future scope

Where C2paSeal could go after the current plan. Nothing here is scheduled
or promised. Items need the maintainer's approval before they become a
phase in [PHASES.md](PHASES.md).

Image features waiting for a yes or no are listed in detail in
[PENDING_APPROVAL.md](PENDING_APPROVAL.md).

## Already planned (approved)

| Phase | Work |
|---|---|
| 32 | MP4 and MOV signing and verification with `c2pa.hash.bmff.v3`, including fragmented MP4 (Merkle-tree hashes over fragments) |
| 33 | Video in the web app (with size limits) and in `sealsvc`; a full interop pass across all formats and tools; the API freeze and **v1.0.0** compatibility promise |

## Listed as "Later" in PHASES.md (not scheduled)

- **PDF.** A minimal PDF reader and writer covering only what C2PA needs:
  an embedded-file manifest store attached through an incremental update,
  hard-binding exclusions, a fuzz target, oracle fixtures and interop rows.
- **PKCS #11 hardware security modules.** The Go bindings need CGO, which
  hard rule 1 forbids. It needs either a pure-Go approach (such as talking
  to an HSM's network API) or a rule change.

## Directions beyond the plan

### More media

- **Audio:** WAV (RIFF, so close to the WebP layer), MP3 (ID3) and FLAC.
- **More image formats:** TIFF/DNG, GIF, SVG, JPEG XL; see
  PENDING_APPROVAL.md, F1–F4.
- **Fonts and other documents** the specification covers, after PDF.

### Identity and richer claims

- **Creator identity assertions** (the Creator Assertions Working Group's
  identity assertion), so a manifest can bind a person's or organisation's
  verified identity, not only the signing certificate's.
- **CreativeWork and other metadata assertions** written when signing.
- **Ingredient graphs:** component ingredients, thumbnails, and a
  provenance graph view in the web app.

### Scale and operations

- **Streaming signing and verification** for large files, instead of
  reading the whole file into memory (matters most for video).
- **sealsvc and sealstore at scale:** a shared database or object storage
  instead of local files, multiple replicas, and key rotation without
  restarts.
- **Fingerprint matching** in `sealstore` (perceptual hashes), so a copy
  without a readable watermark can still be matched approximately.

### Reach

- **Browser extension** that verifies images on web pages with the
  WebAssembly build.
- **More CI integrations:** GitLab CI and other systems, alongside the
  GitHub Action.
- **Official C2PA conformance:** taking C2paSeal through the C2PA
  conformance program once v1.0.0 is out.

### Robustness

- **Crop-robust and keyed watermarks** (PENDING_APPROVAL.md, W1–W2).
- **Continuous interop** against new c2patool releases, flagging any
  change in the oracle's output.

## How ideas get here

New ideas go into the "Future work" section of [PROGRESS.md](PROGRESS.md)
as they come up during a phase. This file is the curated summary.
