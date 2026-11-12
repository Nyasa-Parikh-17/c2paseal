package verify

import (
	"bytes"
	"cmp"
	"errors"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
)

// IngredientDelta holds the statuses found while validating one ingredient
// that the ingredient assertion did not already record.
type IngredientDelta struct {
	IngredientAssertionURI string   `json:"ingredientAssertionURI"`
	ValidationDeltas       []Status `json:"validationDeltas"`
}

// maxIngredientDepth bounds ingredient recursion (c2pa-rs uses 200).
const maxIngredientDepth = 200

// scoped is a status logged while validating an ingredient.
type scoped struct {
	ingredientURI string
	status        Status
}

// ingredientChecker walks a manifest's ingredients the way c2pa-rs
// Store::ingredient_checks does.
type ingredientChecker struct {
	manifests map[string]*manifest.Manifest
	opts      *Options
	visited   map[string]bool
	logged    []scoped
	abort     *Status // set if an ingredient's checks end the validation
}

// ingredients validates the ingredients of the active manifest (and theirs,
// recursively) and returns the deltas: statuses not already recorded in the
// validation results stored in the store's ingredient assertions. abort is
// set if an ingredient's checks end the whole validation (see
// checkClaimAbort).
func ingredients(all []*manifest.Manifest, active *manifest.Manifest, opts *Options) (deltas []IngredientDelta, abort *Status) {
	c := &ingredientChecker{manifests: map[string]*manifest.Manifest{}, opts: opts, visited: map[string]bool{active.Label: true}}
	for _, m := range all {
		c.manifests[m.Label] = m
	}
	c.check(active, 0)
	if c.abort != nil {
		return nil, c.abort
	}
	if len(c.logged) == 0 {
		return nil, nil
	}

	stored := storedStatuses(all)
	var out []IngredientDelta
	index := map[string]int{}
	for _, l := range c.logged {
		s := l.status
		// Statuses about the active manifest are always kept, so an
		// ingredient assertion cannot cancel a genuine failure.
		if manifestOfURI(s.URL) != active.Label && containsStatus(stored, s) {
			continue
		}
		i, ok := index[l.ingredientURI]
		if !ok {
			i = len(out)
			index[l.ingredientURI] = i
			out = append(out, IngredientDelta{IngredientAssertionURI: l.ingredientURI})
		}
		out[i].ValidationDeltas = append(out[i].ValidationDeltas, s)
	}
	return out, nil
}

func (c *ingredientChecker) log(uri string, statuses ...Status) {
	for _, s := range statuses {
		c.logged = append(c.logged, scoped{uri, s})
	}
}

func (c *ingredientChecker) check(m *manifest.Manifest, depth int) {
	if depth >= maxIngredientDepth {
		return
	}
	for _, a := range m.Assertions {
		base := assertion.BaseLabel(a.Label)
		if base != "c2pa.ingredient" && !strings.HasPrefix(base, "c2pa.ingredient.v") {
			continue
		}
		uri := assertionURL(m.Label, a.Label)
		ing, err := decodeIngredient(a)
		if err != nil {
			c.log(uri, Status{Code: AssertionIngredientMalformed, URL: a.Label, Explanation: "ingredient assertion could not be parsed"})
			return
		}
		if ing.ref == nil {
			if ing.relationship != "inputTo" {
				c.log(uri, Status{Code: IngredientUnknownProv, URL: uri, Explanation: cmp.Or(ing.title, "no title") + ": ingredient does not have provenance"})
			}
			continue
		}
		if ing.version >= 3 && !ing.hasResults {
			c.log(uri, Status{Code: AssertionIngredientMalformed, URL: uri, Explanation: "ingredient V3 must have validation results"})
		}
		label := manifestOfURI(ing.ref.URL)
		target := c.manifests[label]
		if target == nil {
			c.log(uri, Status{Code: IngredientManifestMissing, URL: label, Explanation: "ingredient not found"})
			continue
		}
		alg := cmp.Or(ing.ref.Alg, target.Claim.Alg, manifest.DefaultAlg)
		switch {
		case hashMatches(alg, target.Box, nil, ing.ref.Hash):
			c.log(uri, Status{Code: IngredientManifestValidated, URL: ing.ref.URL, Explanation: "ingredient hash matched"})
		case hashMatches(alg, nil, target.Claim.Raw, ing.ref.Hash):
			// Before C2PA 1.3 the ingredient hash covered the claim bytes,
			// not the manifest box; c2pa-rs accepts it and logs nothing.
		default:
			c.log(uri, Status{Code: IngredientManifestMismatch, URL: ing.ref.URL, Explanation: "ingredient hash incorrect"})
		}
		statuses, abort := checkClaimAbort(target, c.opts)
		if abort != nil && c.abort == nil {
			c.abort = abort
		}
		c.log(uri, statuses...)
		if !c.visited[target.Label] {
			c.visited[target.Label] = true
			c.check(target, depth+1)
		}
	}
}

// ingredientInfo is the part of an ingredient assertion validation needs.
type ingredientInfo struct {
	version      int
	relationship string
	title        string
	ref          *manifest.HashedURI // activeManifest (v3) or c2pa_manifest (v1, v2)
	hasResults   bool
	statuses     []Status // validation results recorded in the assertion
}

func decodeIngredient(a assertion.Assertion) (*ingredientInfo, error) {
	c := a.Box.Contents()
	if len(c) == 0 || c[0].Type != "cbor" {
		return nil, errNotCBOR
	}
	var raw map[string]any
	if err := cbormode.Dec.Unmarshal(c[0].Payload, &raw); err != nil {
		return nil, err
	}
	info := &ingredientInfo{version: 1}
	if base := assertion.BaseLabel(a.Label); strings.HasPrefix(base, "c2pa.ingredient.v") {
		info.version = int(base[len(base)-1] - '0')
	}
	info.relationship, _ = raw["relationship"].(string)
	info.title, _ = raw["dc:title"].(string)
	for _, key := range []string{"activeManifest", "c2pa_manifest"} {
		if h, ok := hashedURI(raw[key]); ok {
			info.ref = h
			break
		}
	}
	manifestLabel := ""
	if info.ref != nil {
		manifestLabel = manifestOfURI(info.ref.URL)
	}
	if vr, ok := raw["validationResults"].(map[string]any); ok {
		info.hasResults = true
		info.statuses = append(info.statuses, statusGroup(vr["activeManifest"], manifestLabel)...)
		if deltas, ok := vr["ingredientDeltas"].([]any); ok {
			for _, d := range deltas {
				if dm, ok := d.(map[string]any); ok {
					info.statuses = append(info.statuses, statusGroup(dm["validationDeltas"], manifestLabel)...)
				}
			}
		}
	} else if list, ok := raw["validationStatus"].([]any); ok {
		info.statuses = statusList(list, manifestLabel)
	}
	return info, nil
}

var errNotCBOR = errors.New("ingredient is not a CBOR assertion")

func hashedURI(v any) (*manifest.HashedURI, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	url, _ := m["url"].(string)
	hash, _ := m["hash"].([]byte)
	alg, _ := m["alg"].(string)
	if url == "" {
		return nil, false
	}
	return &manifest.HashedURI{URL: url, Alg: alg, Hash: hash}, true
}

// statusGroup flattens a {success, informational, failure} map.
func statusGroup(v any, manifestLabel string) []Status {
	g, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []Status
	for _, k := range []string{"success", "informational", "failure"} {
		if list, ok := g[k].([]any); ok {
			out = append(out, statusList(list, manifestLabel)...)
		}
	}
	return out
}

// statusList reads recorded statuses, making relative URLs absolute to the
// ingredient's manifest (c2pa-rs ValidationStatus::make_absolute).
func statusList(list []any, manifestLabel string) []Status {
	var out []Status
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		code, _ := m["code"].(string)
		url, _ := m["url"].(string)
		if manifestLabel != "" && strings.HasPrefix(url, manifest.JUMBFURIPrefix) {
			url = absoluteURI(manifestLabel, url)
		}
		out = append(out, Status{Code: code, URL: url})
	}
	return out
}

// storedStatuses collects the recorded validation results of every
// ingredient assertion in the store.
func storedStatuses(all []*manifest.Manifest) []Status {
	var out []Status
	for _, m := range all {
		for _, a := range m.Assertions {
			if strings.HasPrefix(assertion.BaseLabel(a.Label), "c2pa.ingredient") {
				if info, err := decodeIngredient(a); err == nil {
					out = append(out, info.statuses...)
				}
			}
		}
	}
	return out
}

// containsStatus compares the way c2pa-rs ValidationStatus equality does:
// code, URL and kind.
func containsStatus(list []Status, s Status) bool {
	for _, x := range list {
		if x.Code == s.Code && x.URL == s.URL && x.Kind() == s.Kind() {
			return true
		}
	}
	return false
}

// hashMatches reports whether want is the hash of box (its content, as
// HashBox computes it) or, with box nil, of data.
func hashMatches(alg string, box *jumbf.Box, data []byte, want []byte) bool {
	if box != nil {
		sum, err := manifest.HashBox(alg, box)
		return err == nil && bytes.Equal(sum, want)
	}
	h, err := manifest.NewHash(alg)
	if err != nil {
		return false
	}
	h.Write(data)
	return bytes.Equal(h.Sum(nil), want)
}

// referencedManifests reports every ingredient manifest that the active
// manifest's ingredient tree references but the store lacks, the way the
// c2pa-rs pre-pass get_claim_referenced_manifests does before any claim is
// checked. Statuses go to the active manifest, with the label as URL.
func referencedManifests(all []*manifest.Manifest, active *manifest.Manifest) []Status {
	byLabel := map[string]*manifest.Manifest{}
	for _, m := range all {
		byLabel[m.Label] = m
	}
	var out []Status
	visited := map[string]bool{}
	var walk func(m *manifest.Manifest, depth int)
	walk = func(m *manifest.Manifest, depth int) {
		if depth >= maxIngredientDepth || visited[m.Label] {
			return
		}
		visited[m.Label] = true
		for _, a := range m.Assertions {
			base := assertion.BaseLabel(a.Label)
			if base != "c2pa.ingredient" && !strings.HasPrefix(base, "c2pa.ingredient.v") {
				continue
			}
			ing, err := decodeIngredient(a)
			if err != nil || ing.ref == nil {
				continue
			}
			label := manifestOfURI(ing.ref.URL)
			if target := byLabel[label]; target != nil {
				walk(target, depth+1)
			} else {
				out = append(out, Status{Code: IngredientManifestMissing, URL: label, Explanation: "ingredient manifest missing"})
			}
		}
	}
	walk(active, 0)
	return out
}
