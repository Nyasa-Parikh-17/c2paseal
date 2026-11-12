# Official C2PA trust lists

`C2PA-TRUST-LIST.pem` (claim signer anchors) and `C2PA-TSA-TRUST-LIST.pem`
(time-stamp authority anchors) from
<https://github.com/c2pa-org/conformance-public/tree/main/trust-list>,
commit `87190b28aa5687a6f356d85429ecca7b47f16d2d`, © C2PA, licensed under
Creative Commons Attribution 4.0 International (CC BY 4.0). Unchanged.

Load them with `c2paseal.LoadTrustList` or `c2paseal verify --trust <file>`
(repeat `--trust` for both). No fixture in `testdata/` is signed by a
certificate on these lists yet: the public sample files checked so far are
signed by test PKIs or by CAs that are not on them (PROGRESS.md, Phase 20).
