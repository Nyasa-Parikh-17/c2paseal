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
| Signature algorithm | ES256 (ECDSA P-256, SHA-256) |
| Hash algorithm | SHA-256 |
| Hard binding | `c2pa.hash.data` with `exclusions` and `pad` |
| Assertions | `c2pa.actions` (v2), `c2pa.hash.data`, `c2pa.ingredient` (v1–v3), `stds.schema-org.CreativeWork`, `c2pa.thumbnail.claim.jpeg`; others read as raw CBOR |
| Ingredients | Validated recursively (hash, claim, signature), with deltas against the recorded results. Written when re-signing: the parent's manifests are kept byte for byte and the new manifest adds `c2pa.ingredient.v3` (`parentOf`, `activeManifest`, `claimSignature`, `validationResults`) plus a `c2pa.opened` action (§18.15) |
| Manifest location | Embedded; or outside the file (§11.4, §11.5, §15.5.3): a `.c2pa` sidecar next to the asset, or a remote store referenced by XMP `dcterms:provenance` (JPEG APP1, PNG `iTXt`), served as `application/c2pa`. An unfetched or unreachable remote store gives `manifest.inaccessible`. Fetching is opt-in |
| Certificates | X.509 chain from `x5chain`, key usage and C2PA EKU checks, configurable trust anchors |
| Time-stamps | RFC 3161 token in the COSE unprotected header (read and sign) |
| Operations | Read, Verify, Sign |

## Out of scope

- Video and ISO BMFF (`c2pa.hash.bmff`), and every other format.
- Soft bindings and watermarks.
- HTTP `Link` header discovery of remote manifests (§15.5.3.2) and cloud manifest services.
- Signature algorithms other than ES256 (ES384, ES512, PS*, Ed25519).
- Ingredient relationships other than `parentOf` when signing (`componentOf`, `inputTo`).
- Update manifests and manifest editing.
- OCSP and CRL revocation checks.
- CAWG identity assertions.
