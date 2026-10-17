package manifest

import (
	"errors"
	"fmt"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/cose"
)

// Box labels inside a manifest.
const (
	LabelStore      = "c2pa"
	LabelAssertions = "c2pa.assertions"
	LabelSignature  = "c2pa.signature"
)

// ErrMalformedManifest wraps structural problems with a manifest superbox.
var ErrMalformedManifest = errors.New("malformed manifest")

// Manifest is one manifest from a manifest store, decoded but not verified.
type Manifest struct {
	Label        string // e.g. "urn:c2pa:…"
	Box          *jumbf.Box
	ClaimBox     *jumbf.Box
	Claim        *Claim
	Assertions   []assertion.Assertion
	SignatureBox *jumbf.Box

	// Signature is the decoded COSE_Sign1, or nil with SignatureErr set if
	// it could not be decoded. Not verified.
	Signature    *cose.Sign1
	SignatureErr error

	// HashChecks holds one result per assertion reference in the claim.
	// Set by DecodeStore.
	HashChecks []URICheck
}

// Assertion returns the assertion with the given label, or nil.
func (m *Manifest) Assertion(label string) *assertion.Assertion {
	for i := range m.Assertions {
		if m.Assertions[i].Label == label {
			return &m.Assertions[i]
		}
	}
	return nil
}

// DecodeManifest decodes a manifest superbox: its claim, its assertion
// store and the location of its signature. Assertion decode problems are
// recorded per assertion (Assertion.Err), not returned.
func DecodeManifest(box *jumbf.Box) (*Manifest, error) {
	m := &Manifest{Label: box.Label(), Box: box}
	fail := func(err error) (*Manifest, error) {
		return nil, fmt.Errorf("manifest %q: %w", m.Label, err)
	}
	if box.Child(LabelClaimV1) != nil && box.Child(LabelClaimV2) == nil {
		return fail(fmt.Errorf("%w: claim v1 (c2pa.claim)", ErrUnsupportedClaim))
	}
	m.ClaimBox = box.Child(LabelClaimV2)
	if m.ClaimBox == nil {
		return fail(fmt.Errorf("%w: no %s box", ErrMalformedManifest, LabelClaimV2))
	}
	c := m.ClaimBox.Contents()
	if len(c) != 1 || c[0].Type != "cbor" {
		return fail(fmt.Errorf("%w: claim box does not hold one cbor box", ErrMalformedManifest))
	}
	claim, err := DecodeClaim(c[0].Payload)
	if err != nil {
		return fail(err)
	}
	m.Claim = claim

	m.SignatureBox = box.Child(LabelSignature)
	if m.SignatureBox == nil {
		return fail(fmt.Errorf("%w: no %s box", ErrMalformedManifest, LabelSignature))
	}
	if sc := m.SignatureBox.Contents(); len(sc) == 1 && sc[0].Type == "cbor" {
		m.Signature, m.SignatureErr = cose.Decode(sc[0].Payload)
	} else {
		m.SignatureErr = fmt.Errorf("%w: signature box does not hold one cbor box", ErrMalformedManifest)
	}
	store := box.Child(LabelAssertions)
	if store == nil {
		return fail(fmt.Errorf("%w: no %s box", ErrMalformedManifest, LabelAssertions))
	}
	for _, a := range store.Contents() {
		if a.IsSuperbox() {
			m.Assertions = append(m.Assertions, assertion.Decode(a))
		}
	}
	return m, nil
}

// DecodeStore decodes every manifest in a manifest store superbox, in store
// order. The last one is the active manifest.
func DecodeStore(root *jumbf.Box) ([]*Manifest, error) {
	if root.Label() != LabelStore {
		return nil, fmt.Errorf("manifest: %w: store label %q, want %q", ErrMalformedManifest, root.Label(), LabelStore)
	}
	var out []*Manifest
	for _, b := range root.Contents() {
		if !b.IsSuperbox() {
			continue
		}
		m, err := DecodeManifest(b)
		if err != nil {
			return nil, err
		}
		m.HashChecks = checkRefs(root, m)
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("manifest: %w: store has no manifests", ErrMalformedManifest)
	}
	return out, nil
}
