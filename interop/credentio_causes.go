package main

import (
	"crypto/x509"
	"encoding/asn1"
	"os"
	"slices"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// Credentio's results are compared with C2paSeal's. Each entry explains one
// way they differ; like the entries in causes.go, it matches the exact
// status pattern and a fact computed from the file's bytes, so a change in
// either tool shows up as unexplained. Investigated with c2pa_validate at
// the commit pinned in .github/workflows/interop.yml, reading its crJSON
// explanations and its source.
var credentioCauses = []struct {
	match func(r *row, m mode, seal, cr outcome, f fileFacts) bool
	cause cause
}{
	{
		// Default mode: no trust anchors given, so no signer checks at all.
		match: func(r *row, m mode, seal, cr outcome, f fileFacts) bool {
			return m == modeDefault && cr.Err == "" && f.version == 2 &&
				sameSet(cr.Failure, without(without(seal.Failure, verify.SigningCredentialUntrusted), verify.SigningCredentialExpired)) &&
				slices.Contains(seal.Failure, verify.SigningCredentialUntrusted)
		},
		cause: cause{"Credentio: skips the signer certificate checks when given no trust anchors",
			"In default mode no tool is given trust anchors. c2patool and C2paSeal then check the signer certificate anyway and report it as " +
				"`signingCredential.untrusted` (and `signingCredential.expired` for `broken/expired.jpg`, whose signer expired with no time-stamp). " +
				"Credentio's `c2pa_validate` prints `WARNING: --claim_signer_trust is not provided. Skipping claim signer trust checks.` and runs none of them, " +
				"so it reports no signing-credential status; every other failure is the same as C2paSeal's. " +
				"Its derived state is therefore Trusted for files the others call Valid. In trusted mode the comparison is meaningful."},
	},
	{
		// Trusted mode: the signer has no c2pa-kp-claimSigning EKU.
		match: func(r *row, m mode, seal, cr outcome, f fileFacts) bool {
			return m == modeTrusted && cr.Err == "" && f.version == 2 && f.signer != nil && !f.claimSigningEKU &&
				failSet(cr, verify.SigningCredentialInvalid)
		},
		cause: cause{"Credentio: trusts the given anchors only for the `c2pa-kp-claimSigning` EKU",
			"The signer certificate has the EKUs `id-kp-emailProtection` and `id-kp-documentSigning` but not `c2pa-kp-claimSigning` " +
				"(1.3.6.1.4.1.62558.2.1); this is true of the TEST ONLY PKI and of c2pa-rs's test PKI. " +
				"C2PA 2.4 §14.5.1.2 asks that a claim signer have at least one EKU for which the validator has trust anchors, and §14.4.1 names " +
				"`id-kp-emailProtection` and `id-kp-documentSigning` as EKUs a user may configure. c2patool and C2paSeal accept them with the anchors given " +
				"(c2pa-rs's default EKU list). Credentio's `--claim_signer_trust` configures anchors for `c2pa-kp-claimSigning` only and has no option for other EKUs, " +
				"so it reports `signingCredential.invalid` (`Extended Key Usage c2pa-kp-claimSigning not present`) and stops: it reports none of the file's other failures. " +
				"Not a defect in the file under the spec; adding `c2pa-kp-claimSigning` to the test PKI would let Credentio check the rest (noted as future work)."},
	},
	{
		// C2PA 1.x claims and pre-1.0 stores.
		match: func(r *row, m mode, seal, cr outcome, f fileFacts) bool {
			return cr.Err == "" && (f.version == 1 || f.prerelease || slices.Contains(seal.Failure, verify.Prerelease)) &&
				failSet(cr, "com.google.unsupportedSpecVersion")
		},
		cause: cause{"Credentio: does not validate C2PA 1.x manifests",
			"The active manifest has a C2PA 1.x claim (`c2pa.claim`, label `urn:uuid:…`) or is a pre-1.0 store (container facts give the claim version). " +
				"c2patool and C2paSeal validate 1.x claims with c2pa-rs's rules (Phase 19). Credentio reports only its own code " +
				"`com.google.unsupportedSpecVersion` (`deprecated manifest label format`), so its derived state is Invalid whatever the file holds."},
	},
	{
		// No embedded store: unsigned files.
		match: func(r *row, m mode, seal, cr outcome, f fileFacts) bool {
			return !f.embedded && f.external == "" && strings.Contains(cr.Err, "No manifest store found") && failSet(seal, verify.ClaimMissing)
		},
		cause: cause{"Credentio: reports an error instead of a status",
			"The file has no APP11 C2PA segment / no `caBX` chunk. Credentio exits with `Validation failed: NOT_FOUND: No manifest store found` " +
				"and prints no statuses; C2paSeal reports `claim.missing`. Both reject the file."},
	},
	{
		// No embedded store: sidecar and remote-only files.
		match: func(r *row, m mode, seal, cr outcome, f fileFacts) bool {
			return !f.embedded && f.external != "" && strings.Contains(cr.Err, "No manifest store found") && seal.Err == ""
		},
		cause: cause{"Credentio: does not look for manifest stores outside the file",
			"The file's store is in a `.c2pa` sidecar next to it, or only at the URL in its XMP `dcterms:provenance` (container facts say which). " +
				"C2PA 2.4 §15.5.3 tells validators to look for both; c2patool and C2paSeal do and agree. " +
				"Credentio's `c2pa_validate` reads only the asset and exits with `No manifest store found`."},
	},
	{
		// Broken containers: no oracle status.
		match: func(r *row, m mode, seal, cr outcome, f fileFacts) bool {
			return (failSet(seal, verify.GeneralError) && (strings.Contains(cr.Err, "truncated JPEG box") || strings.Contains(cr.Err, "PNG chunk extends beyond the end"))) ||
				(failSet(seal, verify.ClaimMalformed) && strings.Contains(cr.Err, "could not parse content box"))
		},
		cause: cause{"no oracle: Credentio reports an error instead of a status",
			"The container or the JUMBF structure is broken by `scripts/mkbroken` (a segment or chunk cut off by the end of the file, or a box length past the end of the store; " +
				"container facts give the numbers). c2patool also exits with an error here, so there is no oracle status. " +
				"Credentio exits with a parse error (`truncated JPEG box`, `PNG chunk extends beyond the end of the file`, `could not parse content box`); " +
				"C2paSeal reports `general.error` or `claim.malformed`. Every tool rejects the file."},
	},
	{
		// Tampered assertion: Credentio treats it as undeclared.
		match: func(r *row, m mode, seal, cr outcome, f fileFacts) bool {
			if m != modeDefault || cr.Err != "" || !slices.Contains(seal.Failure, verify.AssertionHashedURIMismatch) ||
				!slices.Contains(cr.Failure, verify.AssertionHashedURIMismatch) || !slices.Contains(cr.Failure, "assertion.undeclared") {
				return false
			}
			want := []string{verify.AssertionHashedURIMismatch, "assertion.undeclared"}
			if slices.Contains(seal.Failure, verify.AssertionDataHashMismatch) {
				want = append(want, "claim.hardBindings.missing")
			}
			return sameSet(cr.Failure, want)
		},
		cause: cause{"Credentio: treats an assertion whose hash does not match as undeclared",
			"`scripts/mkbroken` changed one byte inside an assertion (container facts: its hash no longer matches its hashed URI in the claim): " +
				"the action name in `c2pa.actions.v2` (`assertion-flip.jpg`), or the recorded hash in `c2pa.hash.data` (`wrong-hash.*`). " +
				"All tools report `assertion.hashedURI.mismatch`. c2patool and C2paSeal still read the assertion and report what is wrong with it " +
				"(`assertion.action.malformed`, or `assertion.dataHash.mismatch` from comparing the recorded hash with the image). " +
				"Credentio drops the assertion as `assertion.undeclared`; without `c2pa.hash.data` the claim has no hard binding, so it reports `claim.hardBindings.missing`. " +
				"Different codes, same verdict: every tool finds the file Invalid. (In default mode Credentio also skips the signer checks, see above; " +
				"in trusted mode it stops at the EKU check.)"},
	},
}

// fileFacts are the properties of a file the Credentio causes depend on.
type fileFacts struct {
	embedded        bool   // the file holds a manifest store
	external        string // "sidecar" or "remote" when the store is elsewhere
	version         int    // the active claim's version (0: none)
	prerelease      bool
	signer          *x509.Certificate // the active manifest's signer
	claimSigningEKU bool              // signer has c2pa-kp-claimSigning
}

var oidClaimSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62558, 2, 1}

func factsOf(path string) fileFacts {
	var f fileFacts
	b, err := os.ReadFile(path)
	if err != nil {
		return f
	}
	f.external, _ = externalLocation(path, b)
	_, root, err := asset.Extract(b)
	if err != nil || root == nil {
		return f
	}
	f.embedded = true
	ms, err := manifest.DecodeStore(root)
	if err != nil || len(ms) == 0 {
		return f
	}
	active := ms[len(ms)-1]
	if active.Claim != nil {
		f.version = active.Claim.Version
		f.prerelease = verify.IsPrerelease(active)
	}
	if active.Signature != nil && len(active.Signature.X5Chain) > 0 {
		if c, err := x509.ParseCertificate(active.Signature.X5Chain[0]); err == nil {
			f.signer = c
			for _, u := range c.UnknownExtKeyUsage {
				if u.Equal(oidClaimSigning) {
					f.claimSigningEKU = true
				}
			}
		}
	}
	return f
}

// explainCredentio explains how Credentio's result differs from C2paSeal's,
// or returns nil if no entry matches.
func explainCredentio(r *row, m mode) *cause {
	seal, cr := r.find("C2paSeal", m), r.find("Credentio", m)
	f := factsOf(r.Item.Path)
	for _, c := range credentioCauses {
		if c.match(r, m, seal, cr, f) {
			cc := c.cause
			return &cc
		}
	}
	return nil
}
