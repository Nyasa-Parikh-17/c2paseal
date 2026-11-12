package main

import (
	"os"
	"slices"
	"strings"

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
