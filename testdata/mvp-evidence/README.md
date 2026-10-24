# MVP evidence

Unsigned JPEG fixtures signed by **C2paSeal** (ES256, TEST ONLY PKI in
`testdata/pki`), then checked by c2patool and by C2paSeal itself.
Regenerate with `go run ./scripts/mvp-evidence` from the repo root.

- Generated: 2026-10-24
- Validator: c2patool 0.27.21
- `*.c2patool*.json` are c2patool's output, saved unedited.

The test certificates chain to a root nobody trusts, so by default the only
failure is `signingCredential.untrusted` (state `Valid`). With the test root
trusted there are no failures (state `Trusted`).

| File | c2patool (default trust) | c2patool failures | c2patool (test root trusted) | failures | C2paSeal verify | C2paSeal failures |
|---|---|---|---|---|---|---|
| exif.jpg | Valid | signingCredential.untrusted | Trusted | none | Valid | signingCredential.untrusted |
| large.jpg | Valid | signingCredential.untrusted | Trusted | none | Valid | signingCredential.untrusted |
| small.jpg | Valid | signingCredential.untrusted | Trusted | none | Valid | signingCredential.untrusted |
