package main

import (
	"os"
	"slices"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// cause explains a disagreement. Entries were written after investigating
// the bytes and each tool's own explanation. Each entry's match checks the
// exact status pattern it explains, so if a tool's behaviour changes the
// disagreement shows up as unexplained instead of keeping a stale reason.
type cause struct {
	Who  string // which tool deviates, or "no oracle"
	Text string
}

var causes = []struct {
	match func(r *row, m mode) bool
	cause cause
}{
	{
		// Files without any manifest store.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			return failSet(seal, verify.ClaimMissing) && tool.Err != "" && strings.Contains(tool.Err, "No claim found") && agreeOrSkipped(seal, mcp)
		},
		cause: cause{"c2patool: reports an error instead of a status", "The file has no APP11 C2PA segment / no `caBX` chunk (see container facts). " +
			"c2patool exits with `Error: No claim found` and prints no validation statuses; C2paSeal and c2pa-mcp both report the C2PA failure code `claim.missing`. " +
			"Not an interoperability problem: all three reject the file. C2paSeal's mapping is required by CLAUDE.md rule 3 (bad input becomes a status code, not an error)."},
	},
	{
		// JUMBF box length running past the store.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			return failSet(seal, verify.ClaimMalformed) && strings.Contains(tool.Err, "claim superbox not found") && (mcp.Skipped || failSet(mcp, verify.ClaimMissing))
		},
		cause: cause{"no oracle: three different answers", "`scripts/mkbroken` set the 4-byte LBox of the `c2pa.assertions` superbox to `0x7FFFFFF0`, far past the end of the store " +
			"(container facts give the offset and the claimed versus available length). " +
			"c2patool cannot find the claim superbox and exits with an error; c2pa-mcp finds `no parseable manifest in store` and reports `claim.missing`; " +
			"C2paSeal's JUMBF parser rejects the box length and reports `claim.malformed`, because a store is present but its structure is broken. " +
			"With no status from the oracle this is a judgement call, recorded in PROGRESS.md (Phase 9). All three reject the file."},
	},
	{
		// APP11 segment cut short by the end of the file.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			return failSet(seal, verify.GeneralError) && strings.Contains(tool.Err, "could not be parsed") && (mcp.Skipped || failSet(mcp, verify.ClaimMissing))
		},
		cause: cause{"no oracle: three different answers", "`scripts/mkbroken` cut the file in the middle of the first APP11 segment: its length field declares more bytes than remain " +
			"(container facts give both numbers). The file is no longer a well-formed JPEG. c2patool exits with `Could not parse input JPEG`; c2pa-mcp reports `claim.missing` (`no C2PA manifest found`); " +
			"C2paSeal's segment walker fails and `Verify` maps that to `general.error`. All three reject the file; the status code differs because there is no oracle status to follow."},
	},
	{
		// timeStamp.untrusted: failure for c2pa-mcp, informational elsewhere.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			if mcp.Skipped || key(seal) != key(tool) || !slices.Contains(seal.Info, verify.TimeStampUntrusted) {
				return false
			}
			return sameSet(mcp.Failure, append(slices.Clone(seal.Failure), verify.TimeStampUntrusted))
		},
		cause: cause{"c2pa-mcp: classifies `timeStamp.untrusted` as a failure", "The COSE unprotected header carries one `sigTst2` RFC 3161 token whose TSA certificate does not chain to an anchor that tool was given " +
			"(container facts name the TSA; in default mode the local test TSA is unknown to every tool, and in trusted mode DigiCert's TSA is not in the test anchors). " +
			"All tools agree the token is untrusted. c2patool (c2pa-rs) and C2paSeal log `timeStamp.untrusted` as informational, ignore the token's time and check the signer against the current time, " +
			"so the manifest stays Valid. c2pa-mcp logs the same code with severity `failure`, which makes the manifest invalid under the common state rule. " +
			"C2paSeal follows c2patool, the project's oracle (CLAUDE.md rule 4)."},
	},
	{
		// Actions rules on a tampered actions assertion.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			if mcp.Skipped || key(seal) != key(tool) || !slices.Contains(seal.Failure, verify.AssertionActionMalformed) {
				return false
			}
			return sameSet(mcp.Failure, without(seal.Failure, verify.AssertionActionMalformed))
		},
		cause: cause{"c2pa-mcp: does not evaluate the actions rules here", "`scripts/mkbroken` changed one byte inside the `c2pa.actions.v2` CBOR: the action name `c2pa.created` became `c2pa.createD` " +
			"(container facts: the actions assertion's hash no longer matches its hashed URI in the claim). " +
			"All three tools report `assertion.hashedURI.mismatch`. c2patool and C2paSeal also decode the assertion and apply the actions rules " +
			"(the first action must be `c2pa.created` or `c2pa.opened`), giving `assertion.action.malformed`. c2pa-mcp reports no actions-rule status for this file; " +
			"whether it skips those rules for mismatched assertions or always, this corpus does not show. Every tool finds the file Invalid."},
	},
	{
		// Expired signer: c2pa-mcp stops before evaluating trust.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			if mcp.Skipped || key(seal) != key(tool) || !slices.Contains(seal.Failure, verify.SigningCredentialExpired) || !slices.Contains(seal.Failure, verify.SigningCredentialUntrusted) {
				return false
			}
			return sameSet(mcp.Failure, without(seal.Failure, verify.SigningCredentialUntrusted))
		},
		cause: cause{"c2pa-mcp: omits the trust status once the signer has expired", "The signing certificate in `x5chain` expired before validation time and the signature has no time-stamp " +
			"(container facts: signer validity window, 0 time-stamp tokens). All tools report `signingCredential.expired`. " +
			"c2patool and C2paSeal check expiry and trust separately and, without anchors, also report `signingCredential.untrusted`; " +
			"c2pa-mcp's chain check stops at the expiry error (`x509: certificate has expired or is not yet valid`), so it never reports trust. " +
			"With the test root trusted, all three agree."},
	},
	{
		// Sidecar and remote-only manifest stores.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			b, err := os.ReadFile(r.Item.Path)
			if err != nil || mcp.Skipped || tool.Skipped || key(seal) != key(tool) {
				return false
			}
			where, _ := externalLocation(r.Item.Path, b)
			return where != "" && failSet(mcp, verify.ClaimMissing)
		},
		cause: cause{"c2pa-mcp: does not look for manifest stores outside the file", "The file has no embedded store (no APP11 C2PA segment / no `caBX` chunk); " +
			"its store is in a `.c2pa` sidecar next to it, or only at the URL in its XMP `dcterms:provenance` (container facts say which). " +
			"C2PA 2.4 §15.5.3 tells validators to look for both. c2patool reads the sidecar, or fetches the URL (served by the harness on " + remoteAddr + "), " +
			"and C2paSeal does the same (`VerifyFile` finds the sidecar; the harness turns on `FetchRemote`); the two agree. " +
			"c2pa-mcp `verify` has no sidecar or remote option and reports `claim.missing` (`no C2PA manifest found`)."},
	},
	{
		// C2PA 1.x claims: the time-stamp authority's trust.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			return v1Stamp(r, seal, tool, mcp) && sameSet(mcp.Failure, append(slices.Clone(seal.Failure), verify.TimeStampUntrusted))
		},
		cause: cause{"c2pa-mcp: checks the time-stamp authority's trust on C2PA 1.x claims", v1StampText},
	},
	{
		// C2PA 1.x claims with an ingredient whose recorded results hold failures.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			return v1Stamp(r, seal, tool, mcp) &&
				sameSet(mcp.Failure, append(slices.Clone(seal.Failure), verify.TimeStampUntrusted, verify.ClaimSignatureMismatch, verify.TimeStampMismatch))
		},
		cause: cause{"c2pa-mcp: reports ingredient failures the ingredient assertion already records", v1StampText + " " +
			"In addition, the active manifest's `c2pa.ingredient.v2` records `claimSignature.mismatch` in its `validationStatus`: the ingredient's own signature was " +
			"already bad when the file was made (the c2pa-rs corpus builds this file to test exactly that). c2patool and C2paSeal report only deltas, statuses not " +
			"already recorded in the ingredient assertion, so the known failure does not count against the active manifest. c2pa-mcp reports the ingredient's " +
			"`claimSignature.mismatch` and `timeStamp.mismatch` as failures of the file."},
	},
	{
		// C2PA 1.x claims with an ingredient manifest that is not in the store.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			if !v1Stamp(r, seal, tool, mcp) || !slices.Contains(seal.Failure, verify.IngredientManifestMissing) {
				return false
			}
			want := append(without(seal.Failure, verify.IngredientManifestMissing), verify.TimeStampUntrusted, verify.IngredientManifestMismatch)
			return sameSet(mcp.Failure, want)
		},
		cause: cause{"c2pa-mcp: reports a missing ingredient manifest as a mismatch", v1StampText + " " +
			"In addition, one ingredient's `c2pa_manifest` URI names a manifest label (`contentbeef:urn:uuid:…`) that is not in the store; the c2pa-rs corpus edits " +
			"the label to test this, which also breaks that assertion's hashed URI. c2patool and C2paSeal report `ingredient.manifest.missing` " +
			"(c2pa-rs checks the referenced manifests before validating any claim). c2pa-mcp reports `ingredient.manifest.mismatch`. All three find the file Invalid."},
	},
	{
		// timeStamp.mismatch: failure for c2pa-mcp, informational elsewhere.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			if mcp.Skipped || key(seal) != key(tool) || !slices.Contains(seal.Info, verify.TimeStampMismatch) {
				return false
			}
			return sameSet(mcp.Failure, append(slices.Clone(seal.Failure), verify.TimeStampMismatch))
		},
		cause: cause{"c2pa-mcp: classifies `timeStamp.mismatch` as a failure", "The claim was changed after signing (the c2pa-rs corpus edits the claim generator), " +
			"so the claim signature fails and the 1.x `sigTst` token, which covers the claim, no longer matches either (container facts give the token). " +
			"All three tools report `claimSignature.mismatch` and `timeStamp.mismatch`. c2patool and C2paSeal log `timeStamp.mismatch` as informational, as every " +
			"time-stamp status is in C2PA 2.4; c2pa-mcp logs it as a failure. The file is Invalid for every tool because of the signature."},
	},
	{
		// Signer revoked by a stapled OCSP response.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			return failSet(seal, verify.SigningCredentialRevoked) && strings.Contains(tool.Err, "the certificate is not trusted") &&
				(mcp.Skipped || (mcp.State == "Trusted" && slices.Contains(mcp.Info, "signingCredential.revocation.unknown")))
		},
		cause: cause{"no oracle: c2patool refuses the file", "The signature staples an OCSP response (COSE unprotected header `rVals.ocspVals`) from the TEST ONLY responder, " +
			"saying the signer certificate is revoked (container facts). In trusted mode the responder chains to the test root, so the response counts. " +
			"c2pa-rs then logs `signingCredential.ocsp.revoked` and returns an error that ends the whole validation, so c2patool prints " +
			"`the certificate is not trusted` and no statuses. C2paSeal does the same check and, since c2patool reads nothing, reports that code as its one " +
			"failure (CLAUDE.md rule 3). c2pa-mcp does not read stapled responses (`signingCredential.revocation.unknown`) and finds the file Trusted. " +
			"In default mode the responder is not trusted, the response is ignored by both C2paSeal and c2patool, and the tools agree."},
	},
	{
		// Prerelease (pre-1.0) manifests.
		match: func(r *row, m mode) bool {
			seal, tool, mcp := r.find("C2paSeal", m), r.find("c2patool", m), r.find("c2pa-mcp", m)
			return failSet(seal, verify.Prerelease) && strings.Contains(tool.Err, "Prerelease claim found") &&
				(mcp.Skipped || failSet(mcp, verify.ClaimSignatureMismatch, verify.AssertionHashedURIMismatch))
		},
		cause: cause{"no oracle: c2patool refuses the file", "The store was written before C2PA 1.0: the claim's hash for the first assertion is the SHA-256 of the " +
			"assertion's payload alone, not of its JUMBF box, the manifest URIs have no leading `/c2pa/` slash, and the COSE signature has trailing data " +
			"(container facts). c2pa-rs detects the old hashing and refuses to read the store (`Prerelease claim found`); C2paSeal applies the same test " +
			"(`verify.IsPrerelease`) and reports the c2pa-rs code for it, `com.adobe.prerelease`, as its one failure (CLAUDE.md rule 3). " +
			"c2pa-mcp reads the store as current data and reports `claimSignature.mismatch` and `assertion.hashedURI.mismatch`. All three reject the file."},
	},
}

// v1StampText explains why c2pa-mcp finds 1.x files with a time-stamp
// invalid.
const v1StampText = "The active manifest has a C2PA 1.x claim (`c2pa.claim`) signed PS256, with a 1.x `sigTst` RFC 3161 token from a " +
	"public TSA (container facts name the signer and the TSA). For 1.x claims c2pa-rs does not check the time-stamp authority's trust (claim.rs `verify_claim` turns off " +
	"`verify_timestamp_trust` when `claim.version() == 1`), so c2patool reports `timeStamp.trusted` and uses the token's time; C2paSeal does the same. " +
	"c2pa-mcp checks the TSA against its anchors on every claim, finds it untrusted and logs `timeStamp.untrusted` as a failure, so the file is Invalid for it."

// v1Stamp: C2paSeal and c2patool agree on a 1.x claim whose time-stamp
// they both accept without checking the authority, and c2pa-mcp ran.
func v1Stamp(r *row, seal, tool, mcp outcome) bool {
	if mcp.Skipped || key(seal) != key(tool) || !slices.Contains(seal.Success, verify.TimeStampTrusted) {
		return false
	}
	b, err := os.ReadFile(r.Item.Path)
	if err != nil {
		return false
	}
	st, err := c2paseal.ReadBytes(b)
	return err == nil && st.Active.Claim.Version == 1
}

func explain(r *row, m mode) *cause {
	for _, c := range causes {
		if c.match(r, m) {
			cc := c.cause
			return &cc
		}
	}
	return nil
}

// failSet reports whether o's failures are exactly codes (as a set).
func failSet(o outcome, codes ...string) bool {
	return !o.Skipped && o.Err == "" && sameSet(o.Failure, codes)
}

func agreeOrSkipped(a, b outcome) bool { return b.Skipped || key(a) == key(b) }

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

func without(list []string, drop string) []string {
	return slices.DeleteFunc(slices.Clone(list), func(s string) bool { return s == drop })
}

func algName(alg int64) string { return cose.AlgName(alg) }
