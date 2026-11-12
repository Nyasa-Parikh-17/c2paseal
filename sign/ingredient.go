package sign

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// LabelIngredient is the label of the ingredient assertion Sign writes.
const LabelIngredient = "c2pa.ingredient.v3"

// ErrParent is returned when the input already carries a manifest store
// that cannot be kept as the new manifest's parent ingredient. Setting
// Options.NoHistory replaces such a store instead.
var ErrParent = errors.New("sign: existing manifest store cannot be recorded as the parent ingredient")

// parent is the manifest store of the file being re-signed.
type parent struct {
	manifests []*jumbf.Box // every manifest of the parent store, in store order
	active    *manifest.Manifest
	mediaType string
	results   *verify.Result // the parent validated as it was, before re-signing
}

// readParent returns the input's existing manifest store, to be recorded as
// the parent ingredient, or nil if there is none (or NoHistory is set).
func readParent(in []byte, opts *Options) (*parent, error) {
	if opts.NoHistory {
		return nil, nil
	}
	format, root, err := asset.Extract(in)
	switch {
	case errors.Is(err, asset.ErrNoManifest):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrParent, err)
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParent, err)
	}
	p := &parent{active: ms[len(ms)-1], mediaType: "image/" + format}
	for _, m := range ms {
		// The parent manifests are copied into the new store as they are;
		// re-encoding must give back exactly the bytes that were signed.
		if !bytes.Equal(jumbf.Serialize(m.Box), m.Box.Raw) {
			return nil, fmt.Errorf("%w: manifest %s does not re-encode to its original bytes", ErrParent, m.Label)
		}
		p.manifests = append(p.manifests, m.Box)
	}
	if p.active.SignatureBox == nil {
		return nil, fmt.Errorf("%w: active manifest has no signature", ErrParent)
	}
	p.results = verify.File(in, opts.ParentVerify)
	return p, nil
}

// ingredientV3 is a c2pa.ingredient.v3 assertion for a parent asset, with
// the fields c2pa-rs writes for one (C2PA 2.4 §18.15).
type ingredientV3 struct {
	Relationship      string             `cbor:"relationship"`
	Format            string             `cbor:"dc:format,omitempty"`
	ValidationResults validationResults  `cbor:"validationResults"`
	InstanceID        string             `cbor:"instanceID,omitempty"`
	ActiveManifest    manifest.HashedURI `cbor:"activeManifest"`
	ClaimSignature    manifest.HashedURI `cbor:"claimSignature"`
}

type validationResults struct {
	ActiveManifest   statusGroups      `cbor:"activeManifest"`
	IngredientDeltas []ingredientDelta `cbor:"ingredientDeltas,omitempty"`
}

type statusGroups struct {
	Success       []statusRecord `cbor:"success"`
	Informational []statusRecord `cbor:"informational"`
	Failure       []statusRecord `cbor:"failure"`
}

type statusRecord struct {
	Code        string `cbor:"code"`
	URL         string `cbor:"url,omitempty"`
	Explanation string `cbor:"explanation,omitempty"`
}

type ingredientDelta struct {
	URI    string       `cbor:"ingredientAssertionURI"`
	Deltas statusGroups `cbor:"validationDeltas"`
}

func groupStatuses(list []verify.Status) statusGroups {
	g := statusGroups{Success: []statusRecord{}, Informational: []statusRecord{}, Failure: []statusRecord{}}
	for _, s := range list {
		e := statusRecord{Code: s.Code, URL: s.URL, Explanation: s.Explanation}
		switch s.Kind() {
		case verify.Success:
			g.Success = append(g.Success, e)
		case verify.Informational:
			g.Informational = append(g.Informational, e)
		default:
			g.Failure = append(g.Failure, e)
		}
	}
	return g
}

// ingredientCBOR encodes the parent ingredient assertion: hashed URIs to the
// parent's active manifest and its signature, and the parent's validation
// results.
func (p *parent) ingredientCBOR() ([]byte, error) {
	alg := manifest.DefaultAlg
	mh, err := manifest.HashBox(alg, p.active.Box)
	if err != nil {
		return nil, err
	}
	sh, err := manifest.HashBox(alg, p.active.SignatureBox)
	if err != nil {
		return nil, err
	}
	vr := validationResults{ActiveManifest: groupStatuses(p.results.ActiveManifest)}
	for _, d := range p.results.IngredientDeltas {
		vr.IngredientDeltas = append(vr.IngredientDeltas, ingredientDelta{URI: d.IngredientAssertionURI, Deltas: groupStatuses(d.ValidationDeltas)})
	}
	ing := ingredientV3{
		Relationship:      "parentOf",
		Format:            p.mediaType,
		ValidationResults: vr,
		ActiveManifest:    manifest.HashedURI{URL: verify.ManifestURL(p.active.Label), Alg: alg, Hash: mh},
		ClaimSignature:    manifest.HashedURI{URL: verify.SignatureURL(p.active), Alg: alg, Hash: sh},
	}
	if p.active.Claim != nil {
		ing.InstanceID = p.active.Claim.InstanceID
	}
	return cbormode.Enc.Marshal(&ing)
}
