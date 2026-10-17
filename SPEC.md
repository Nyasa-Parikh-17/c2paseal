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
| Assertions | `c2pa.actions` (v2), `c2pa.hash.data`, `stds.schema-org.CreativeWork`, `c2pa.thumbnail.claim.jpeg`; others read as raw CBOR |
| Certificates | X.509 chain from `x5chain`, key usage and C2PA EKU checks, configurable trust anchors |
| Time-stamps | RFC 3161 token in the COSE unprotected header (read and sign) |
| Operations | Read, Verify, Sign |

## Out of scope

- Video and ISO BMFF (`c2pa.hash.bmff`), and every other format.
- Soft bindings and watermarks.
- Remote and cloud manifests.
- Signature algorithms other than ES256 (ES384, ES512, PS*, Ed25519).
- Ingredient validation beyond reading the assertion.
- Update manifests and manifest editing.
- OCSP and CRL revocation checks.
- CAWG identity assertions.
