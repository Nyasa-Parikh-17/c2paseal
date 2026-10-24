package verify

import (
	"errors"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
)

// Action names with special rules.
const (
	actionCreated = "c2pa.created"
	actionOpened  = "c2pa.opened"
	actionPlaced  = "c2pa.placed"
	actionRemoved = "c2pa.removed"
)

// checkClaim validates one claim the way c2pa-rs Claim::verify_claim does:
// signature reference and label, time-stamp, credential and signature, then
// the assertion references and the actions rules.
func checkClaim(m *manifest.Manifest, opts *Options) []Status {
	out := refChecks(m)
	ts, tsTime := timeStamp(m, opts)
	out = append(out, ts...)
	out = append(out, credentials(m, tsTime, opts)...)
	refs, undeclared := assertionRefs(m)
	out = append(out, refs...)
	if !undeclared {
		out = append(out, actions(m)...)
	}
	return out
}

// absoluteURI turns a relative self#jumbf= URI into one rooted at the store.
func absoluteURI(label, uri string) string {
	path := strings.TrimPrefix(uri, manifest.JUMBFURIPrefix)
	if strings.HasPrefix(path, "/") {
		return uri
	}
	return ManifestURL(label) + "/" + path
}

// manifestOfURI returns the manifest label in an absolute URI
// ("self#jumbf=/c2pa/<label>/…"), or "".
func manifestOfURI(uri string) string {
	path, ok := strings.CutPrefix(uri, manifest.JUMBFURIPrefix+"/"+manifest.LabelStore+"/")
	if !ok {
		return ""
	}
	label, _, _ := strings.Cut(path, "/")
	return label
}

// assertionRefs reports each claim reference (match, mismatch, missing or
// outside the manifest) and every assertion the claim does not reference.
// undeclared is true if there were any; c2pa-rs then skips the actions
// rules.
func assertionRefs(m *manifest.Manifest) (out []Status, undeclared bool) {
	referenced := map[string]bool{}
	for _, c := range m.HashChecks {
		url := c.Ref.URL
		abs := absoluteURI(m.Label, url)
		path := strings.TrimPrefix(url, manifest.JUMBFURIPrefix)
		if strings.HasPrefix(path, "/") {
			owner := manifestOfURI(url)
			if owner == "" {
				out = append(out, Status{AssertionHashedURIMismatch, url, "assertion URI malformed: " + url})
				continue
			}
			if owner != m.Label {
				out = append(out, Status{AssertionOutsideManifest, url, "assertion reference to external assertion store: " + url})
			}
		}
		referenced[path[strings.LastIndex(path, "/")+1:]] = true
		switch {
		case errors.Is(c.Err, manifest.ErrUnresolved), errors.Is(c.Err, manifest.ErrBadURI):
			out = append(out, Status{AssertionMissing, abs, "cannot find matching assertion: " + url})
		case c.Match:
			out = append(out, Status{AssertionHashedURIMatch, abs, "hashed uri matched: " + url})
		default:
			out = append(out, Status{AssertionHashedURIMismatch, abs, "hash does not match assertion data: " + url})
		}
	}
	for _, a := range m.Assertions {
		if !referenced[a.Label] {
			out = append(out, Status{AssertionUndeclared, a.Label, "assertion is not referenced by the claim"})
			undeclared = true
		}
	}
	return out, undeclared
}

// actionsRef is an actions assertion in claim order.
type actionsRef struct {
	label string
	value *assertion.Actions
}

// actionAssertions returns the claim's actions assertions from refs, in
// order, skipping ones that are missing or could not be decoded.
func actionAssertions(m *manifest.Manifest, refs []manifest.HashedURI) []actionsRef {
	var out []actionsRef
	for _, r := range refs {
		label := r.URL[strings.LastIndex(r.URL, "/")+1:]
		base := assertion.BaseLabel(label)
		if base != assertion.LabelActions && base != assertion.LabelActionsV2 {
			continue
		}
		if a := m.Assertion(label); a != nil {
			if v, ok := a.Value.(*assertion.Actions); ok {
				out = append(out, actionsRef{label, v})
			}
		}
	}
	return out
}

// actions applies the c2pa-rs actions rules (claim.rs verify_actions) that
// do not depend on ingredient relationships.
func actions(m *manifest.Manifest) []Status {
	var out []Status
	malformed := func(url, why string) { out = append(out, Status{AssertionActionMalformed, url, why}) }

	created := actionAssertions(m, m.Claim.CreatedAssertions)
	gathered := actionAssertions(m, m.Claim.GatheredAssertions)
	all := append(append([]actionsRef(nil), created...), gathered...)

	// 1. every actions assertion needs a non-empty actions array (full stop).
	for _, a := range all {
		if len(a.value.Actions) == 0 {
			malformed(assertionURL(m.Label, a.label), "Actions missing action array")
			return out
		}
	}

	// 2.a the first actions assertion (created, else gathered) must start
	// with c2pa.created or c2pa.opened.
	first := ""
	for _, list := range [][]actionsRef{created, gathered} {
		if len(list) > 0 {
			if act := list[0].value.Actions[0].Action; act == actionCreated || act == actionOpened {
				first = list[0].label
			}
		}
	}
	if first == "" && len(all) > 0 {
		malformed(m.Label, "first action must be created or opened")
	}

	for index, a := range all {
		url := assertionURL(m.Label, a.label)
		for _, act := range a.value.Actions {
			createdOrOpened := act.Action == actionCreated || act.Action == actionOpened
			if act.Action == "" {
				malformed(url, "action must have an action.")
			}
			if first != "" && first != a.label && createdOrOpened {
				malformed(url, "only first action can be created or opened")
			}
			// c2pa-rs compares the index of the actions assertion here.
			if index != 0 && createdOrOpened {
				malformed(url, "created or opened must be first action")
			}
			if act.Action == actionOpened || act.Action == actionPlaced || act.Action == actionRemoved {
				if ings, ok := act.Parameters["ingredients"]; ok {
					if list, _ := ings.([]any); len(list) == 0 {
						out = append(out, Status{AssertionActionIngredientMismatch, url,
							"opened, placed and removed items must have ingredients parameter must be non empty array"})
					}
				} else if _, ok := act.Parameters["ingredient"]; !ok {
					out = append(out, Status{AssertionActionIngredientMismatch, url,
						"opened, placed and removed items must have ingredient(s) parameters"})
				}
			}
			if act.Action == actionCreated && act.DigitalSourceType == "" {
				malformed(url, "c2pa.created action must have a digitalSourceType")
			}
		}
	}
	return out
}

// assertionURL is the absolute URI of an assertion in a manifest.
func assertionURL(manifestLabel, assertionLabel string) string {
	return ManifestURL(manifestLabel) + "/" + manifest.LabelAssertions + "/" + assertionLabel
}

// ManifestURL is the absolute URI of a manifest.
func ManifestURL(label string) string {
	return manifest.JUMBFURIPrefix + "/" + manifest.LabelStore + "/" + label
}

// SignatureURL is the absolute URI of a manifest's signature box.
func SignatureURL(m *manifest.Manifest) string {
	return ManifestURL(m.Label) + "/" + manifest.LabelSignature
}
