// Package c2paseal reads, verifies and signs C2PA Content Credentials in
// JPEG, PNG, WebP, HEIC and AVIF files, without CGO.
//
// The signer needs no CGO, Rust toolchain or external tool. It builds a
// C2PA 2.4 manifest and embeds it in the image: APP11 segments in JPEG, a
// caBX chunk in PNG, a RIFF C2PA chunk in WebP, and the ISO BMFF C2PA uuid
// box in HEIC and AVIF. It binds the manifest to the image bytes with a
// c2pa.hash.data hard binding (c2pa.hash.bmff.v3 for HEIC and AVIF), signs
// it with ES256 and can add an RFC 3161 time-stamp.
//
// The three entry points:
//
//   - [Read] decodes the manifest store of a file without verifying it.
//   - [Verify] and [VerifyFile] validate it and report C2PA status codes
//     (claimSignature.validated, assertion.dataHash.mismatch, ...) and a
//     state: Invalid, Valid or Trusted. Malformed input never makes them
//     fail; it becomes a failure status.
//   - [Sign] signs a file. An existing manifest store is kept and its
//     active manifest recorded as the parent ingredient, so the history
//     survives re-signing; the store can also go in a .c2pa sidecar, with
//     an optional remote URL in the file's XMP.
//
// Signing uses reserve-and-backfill: a placeholder manifest of the final
// size is inserted first, then the hard-binding hash and the signature are
// written in place. The final manifest must have exactly the placeholder's
// length, which is checked before anything is returned.
//
// Scope: JPEG, PNG, WebP, HEIC and AVIF. Signing is ES256 with a v2 claim
// and can record soft bindings (c2pa.soft-binding), such as a watermark
// ID; verifying also accepts ES384, ES512, PS256-512 and Ed25519, and C2PA
// 1.x (claim v1) files. No video yet. The target C2PA specification
// revision is pinned in SPEC.md, and INTEROP.md compares the results with
// c2patool and other validators.
//
// The middleware package signs uploads in an HTTP service. The
// documentation site, with a quickstart and a guide per component, is at
// https://nyasa-parikh-17.github.io/c2paseal/docs/.
//
// The certificates in testdata/pki are TEST ONLY: their private keys are
// public, so files signed with them prove nothing and validators report
// signingCredential.untrusted unless told to trust the test root.
package c2paseal
