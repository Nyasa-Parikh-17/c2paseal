package verify

import (
	"bytes"
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

// State is the overall verdict on a file (C2PA 2.4 validation states).
type State string

const (
	Invalid State = "Invalid"
	Valid   State = "Valid"   // well-formed and intact; signer may be untrusted
	Trusted State = "Trusted" // valid and the signer chains to a trust anchor
)

// Result holds the statuses for the active manifest and, per ingredient,
// those not already recorded in the ingredient assertion. It has the shape
// of c2patool's validation_results.
type Result struct {
	ActiveManifest   []Status          `json:"activeManifest"`
	IngredientDeltas []IngredientDelta `json:"ingredientDeltas,omitempty"`
}

// Statuses returns every status: the active manifest's, then each
// ingredient's deltas.
func (r *Result) Statuses() []Status {
	out := slices.Clone(r.ActiveManifest)
	for _, d := range r.IngredientDeltas {
		out = append(out, d.ValidationDeltas...)
	}
	return out
}

// State applies c2pa-rs's rule (validation_results.rs validation_state):
// Valid needs claimSignature.validated and .insideValidity and no failure
// other than signingCredential.untrusted, in the active manifest and in
// every ingredient delta; Trusted additionally needs
// signingCredential.trusted and no failures at all.
func (r *Result) State() State {
	has := func(code string) bool {
		return slices.ContainsFunc(r.ActiveManifest, func(s Status) bool { return s.Code == code && s.Kind() == Success })
	}
	onlyUntrusted, noFailures := true, true
	for _, s := range r.Statuses() {
		if s.Kind() == Failure {
			noFailures = false
			if s.Code != SigningCredentialUntrusted {
				onlyUntrusted = false
			}
		}
	}
	valid := has(ClaimSignatureValidated) && has(ClaimSignatureInsideValidity) && onlyUntrusted
	switch {
	case valid && noFailures && has(SigningCredentialTrusted):
		return Trusted
	case valid:
		return Valid
	}
	return Invalid
}

// File verifies the C2PA manifest store of a JPEG or PNG held in memory.
// Malformed and unsigned files give failure statuses, never an error.
func File(b []byte, opts *Options) *Result {
	fail := func(code, why string) *Result {
		return &Result{ActiveManifest: []Status{{Code: code, Explanation: why}}}
	}
	_, root, err := asset.Extract(b)
	if errors.Is(err, asset.ErrNoManifest) {
		var st *Status
		root, st = external(b, opts)
		if st != nil {
			return &Result{ActiveManifest: []Status{*st}}
		}
		err = nil
	}
	switch {
	case errors.Is(err, asset.ErrUnsupportedFormat):
		return fail(GeneralError, "unsupported file format")
	case errors.Is(err, asset.ErrMultipleStores):
		return fail(ClaimMultiple, "more than one manifest store")
	case isJUMBFError(err):
		return fail(ClaimMalformed, "manifest store could not be parsed: "+err.Error())
	case err != nil:
		return fail(GeneralError, "asset could not be parsed: "+err.Error())
	}

	ms, err := manifest.DecodeStore(root)
	if err != nil {
		return fail(ClaimMalformed, err.Error())
	}
	for _, m := range ms {
		if IsPrerelease(m) {
			return fail(Prerelease, "prerelease claim found: "+m.Label)
		}
	}
	active := ms[len(ms)-1]
	r := &Result{ActiveManifest: referencedManifests(ms, active)}
	statuses, abort := checkClaimAbort(active, opts)
	if abort != nil {
		return &Result{ActiveManifest: []Status{*abort}}
	}
	r.ActiveManifest = append(r.ActiveManifest, statuses...)
	if r.IngredientDeltas, abort = ingredients(ms, active, opts); abort != nil {
		return &Result{ActiveManifest: []Status{*abort}}
	}
	r.ActiveManifest = append(r.ActiveManifest, hardBinding(active, b)...)
	return r
}

// IsPrerelease reports pre-1.0 manifest data the way c2pa-rs does
// (store.rs is_old_assertion): the claim's hash for the first assertion in
// the store is the hash of the assertion's payload alone, not of its box.
// c2pa-rs refuses to read such a store; File reports com.adobe.prerelease.
func IsPrerelease(m *manifest.Manifest) bool {
	if len(m.Assertions) == 0 {
		return false
	}
	first := m.Assertions[0]
	var ref *manifest.HashedURI
	for _, r := range m.Claim.Assertions() {
		if strings.HasSuffix(r.URL, "/"+first.Label) {
			ref = &r
			break
		}
	}
	if ref == nil {
		return false
	}
	var data []byte
	switch c := first.Box.Contents(); {
	case len(c) == 1 && (c[0].Type == "cbor" || c[0].Type == "json"):
		data = c[0].Payload
	case len(c) == 2 && c[0].Type == "bfdb" && c[1].Type == "bidb":
		data = c[1].Payload
	default:
		return false
	}
	h, err := manifest.NewHash(cmp.Or(ref.Alg, m.Claim.Alg, manifest.DefaultAlg))
	if err != nil {
		return false
	}
	h.Write(data)
	return bytes.Equal(h.Sum(nil), ref.Hash)
}

// isJUMBFError reports whether err came from parsing the JUMBF box tree, as
// opposed to the JPEG or PNG container around it.
func isJUMBFError(err error) bool {
	for _, target := range []error{jumbf.ErrTruncated, jumbf.ErrBadLength, jumbf.ErrNoDescription, jumbf.ErrTooDeep, jumbf.ErrTopLevel} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
