package verify

import (
	"errors"
	"slices"

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
	switch {
	case errors.Is(err, asset.ErrUnsupportedFormat):
		return fail(GeneralError, "unsupported file format")
	case errors.Is(err, asset.ErrNoManifest):
		return fail(ClaimMissing, "could not find active manifest")
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
	active := ms[len(ms)-1]
	r := &Result{ActiveManifest: checkClaim(active, opts)}
	r.IngredientDeltas = ingredients(ms, active, opts)
	r.ActiveManifest = append(r.ActiveManifest, hardBinding(active, b)...)
	return r
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
