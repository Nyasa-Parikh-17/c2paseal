// Package c2paseal reads, verifies and signs C2PA Content Credentials in
// JPEG and PNG files, without CGO.
//
// The signer needs no CGO, Rust toolchain or external tool. It builds a
// C2PA 2.4 manifest, embeds it in the image (APP11 segments for JPEG, a
// caBX chunk for PNG), binds it to the image bytes with a c2pa.hash.data
// hard binding, signs it with ES256 and can add an RFC 3161 time-stamp.
//
// The three entry points:
//
//   - [Read] decodes the manifest store of a file without verifying it.
//   - [Verify] and [VerifyFile] validate it and report C2PA status codes
//     (claimSignature.validated, assertion.dataHash.mismatch, ...) and a
//     state: Invalid, Valid or Trusted. Malformed input never makes them
//     fail; it becomes a failure status.
//   - [Sign] embeds a newly signed manifest, replacing any existing one.
//
// Signing uses reserve-and-backfill: a placeholder manifest of the final
// size is inserted first, then the hard-binding hash and the signature are
// written in place. The final manifest must have exactly the placeholder's
// length, which is checked before anything is returned.
//
// Scope: JPEG and PNG, ES256, c2pa.hash.data. No video or BMFF, no soft
// bindings, no remote manifests. The target C2PA specification revision is
// pinned in SPEC.md, and INTEROP.md compares the results with c2patool and
// other validators.
//
// The certificates in testdata/pki are TEST ONLY: their private keys are
// public, so files signed with them prove nothing and validators report
// signingCredential.untrusted unless told to trust the test root.
package c2paseal
