# C2paSeal — specification scope

## Target revision

**C2PA Technical Specification 2.4**
<https://c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html>

Chosen because it is the revision referenced by `c2pa-rs`, which backs our
oracle (`c2patool` 0.27.x). Field names in code follow this revision
(claim v2: `claim_generator_info`, `created_assertions`, `instanceID`, `alg`,
`signature`, …).

Related standards: JUMBF (ISO/IEC 19566-5), JPEG XT boxes in APP11
(ISO/IEC 18477-3), COSE_Sign1 (RFC 9052), RFC 3161 time-stamps.

## In scope

| Area | Scope |
|---|---|
| Formats | JPEG (APP11 / JPEG XT), PNG (`caBX` chunk) |
| Signature algorithm | Signing: ES256 (ECDSA P-256, SHA-256). Verifying (approved 2026-11-12): also ES384, ES512, PS256, PS384, PS512 (RSASSA-PSS, salt length = digest length) and Ed25519, with the Go standard library; certificates with an id-RSASSA-PSS key are read |
| Claims | Claim v2 (`c2pa.claim.v2`) read and written. Claim v1 (`c2pa.claim`, C2PA 1.x) read only, with c2pa-rs's v1 rules: v1 keys only, no `urn:c2pa:` label check, one actions assertion and no other actions rules, no time-stamp authority trust check, and the pre-1.3 ingredient hash (over the claim bytes) accepted. 1.x `c2pa.credentials` stores are shown, not verified. Pre-1.0 (prerelease) stores are refused (`com.adobe.prerelease`) |
| Hash algorithm | SHA-256 |
| Hard binding | `c2pa.hash.data` with `exclusions` and `pad` |
| Assertions | `c2pa.actions` (v2), `c2pa.hash.data`, `c2pa.ingredient` (v1–v3), `stds.schema-org.CreativeWork`, `c2pa.thumbnail.claim.jpeg`; others read as raw CBOR |
| Ingredients | Validated recursively (hash, claim, signature), with deltas against the recorded results. Written when re-signing: the parent's manifests are kept byte for byte and the new manifest adds `c2pa.ingredient.v3` (`parentOf`, `activeManifest`, `claimSignature`, `validationResults`) plus a `c2pa.opened` action (§18.15) |
| Manifest location | Embedded; or outside the file (§11.4, §11.5, §15.5.3): a `.c2pa` sidecar next to the asset, or a remote store referenced by XMP `dcterms:provenance` (JPEG APP1, PNG `iTXt`), served as `application/c2pa`. An unfetched or unreachable remote store gives `manifest.inaccessible`. Fetching is opt-in |
| Certificates | X.509 chain from `x5chain` (path building through any number of intermediates, in any order), key usage and C2PA EKU checks. Trust: anchors from PEM bundles such as the official C2PA trust lists (`C2PA-TRUST-LIST.pem`, `C2PA-TSA-TRUST-LIST.pem`), c2pa-rs's allowed list of end-entity certificates (PEM or base64 SHA-256) and its trust configuration of extra EKUs |
| Revocation | OCSP (RFC 6960, own reader on the standard library): stapled responses in the COSE unprotected header (`rVals.ocspVals`) are read and, when their responder is a trusted OCSP signer, give `signingCredential.ocsp.notRevoked` or `signingCredential.ocsp.revoked` (which ends validation, as in c2pa-rs); an online check of the signer is opt-in (`signingCredential.ocsp.notRevoked`, `.revoked`, `.unknown`, `.inaccessible`). Signing can staple a response, given or fetched |
| Time-stamps | RFC 3161 token in the COSE unprotected header (read and sign). Verified with our own CMS reader (`verify/tst.go`): the CMS `signingTime` attribute is used when present, an unreadable token gives `timeStamp.malformed` and a CMS signature that does not verify `timeStamp.untrusted`, in c2pa-rs order |
| Operations | Read, Verify, Sign |

## Out of scope

- Video and ISO BMFF (`c2pa.hash.bmff`), and every other format.
- Soft bindings and watermarks.
- HTTP `Link` header discovery of remote manifests (§15.5.3.2) and cloud manifest services.
- Signing with algorithms other than ES256.
- Ingredient relationships other than `parentOf` when signing (`componentOf`, `inputTo`).
- Update manifests and manifest editing.
- CRL revocation checks; OCSP for time-stamp authorities and intermediates; the `c2pa.certificate-status` assertion.
- CAWG identity assertions.
