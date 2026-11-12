package manifest

import (
	"errors"
	"fmt"
	"slices"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
	"github.com/fxamacker/cbor/v2"
)

// Claim labels.
const (
	LabelClaimV2 = "c2pa.claim.v2"
	LabelClaimV1 = "c2pa.claim"
)

// Claim decode errors.
var (
	ErrMalformedClaim   = errors.New("malformed claim")
	ErrUnsupportedClaim = errors.New("unsupported claim version")
)

// HashedURI is a reference to a JUMBF box together with the hash of that box.
type HashedURI struct {
	URL  string `cbor:"url" json:"url"`
	Alg  string `cbor:"alg,omitempty" json:"alg,omitempty"` // empty: inherit the claim's alg
	Hash []byte `cbor:"hash" json:"hash"`
}

// GeneratorInfo is a claim_generator_info map: "name" is required, "version"
// is common, and any other key may appear.
type GeneratorInfo map[string]any

// Name returns the generator name, or "" if absent or not a string.
func (g GeneratorInfo) Name() string { s, _ := g["name"].(string); return s }

// Version returns the generator version, or "" if absent or not a string.
func (g GeneratorInfo) Version() string { s, _ := g["version"].(string); return s }

// Claim is a C2PA claim. Version 2 claims (label c2pa.claim.v2) are the
// ones Sign writes; version 1 claims (label c2pa.claim, C2PA 1.x) are read
// only, and keep their 1.x-only fields in the V1 fields below. Raw holds the
// original CBOR, which is what the signature covers; never re-encode a
// decoded claim to verify it.
type Claim struct {
	InstanceID         string         `cbor:"instanceID" json:"instanceID"`
	ClaimGeneratorInfo GeneratorInfo  `cbor:"claim_generator_info" json:"claim_generator_info"`
	Signature          string         `cbor:"signature" json:"signature"`
	CreatedAssertions  []HashedURI    `cbor:"created_assertions" json:"created_assertions"`
	GatheredAssertions []HashedURI    `cbor:"gathered_assertions,omitempty" json:"gathered_assertions,omitempty"`
	RedactedAssertions []string       `cbor:"redacted_assertions,omitempty" json:"redacted_assertions,omitempty"`
	Title              string         `cbor:"dc:title,omitempty" json:"dc:title,omitempty"`
	Alg                string         `cbor:"alg,omitempty" json:"alg,omitempty"`
	AlgSoft            string         `cbor:"alg_soft,omitempty" json:"alg_soft,omitempty"`
	SpecVersion        string         `cbor:"specVersion,omitempty" json:"specVersion,omitempty"`
	Metadata           map[string]any `cbor:"metadata,omitempty" json:"metadata,omitempty"`

	// Version is 1 or 2.
	Version int `cbor:"-" json:"-"`

	// Claim v1 only. ClaimGeneratorInfo then holds the first entry of the
	// v1 claim_generator_info array, or {"name": ClaimGenerator} without one.
	ClaimGenerator      string          `cbor:"-" json:"-"` // claim_generator
	GeneratorInfoV1     []GeneratorInfo `cbor:"-" json:"-"` // claim_generator_info array
	ClaimGeneratorHints map[string]any  `cbor:"-" json:"-"` // claim_generator_hints
	Format              string          `cbor:"-" json:"-"` // dc:format
	V1Assertions        []HashedURI     `cbor:"-" json:"-"` // assertions

	Raw []byte `cbor:"-" json:"-"`
}

// Assertions returns the claim's assertion references: for v2 the created
// then the gathered ones, for v1 its single list.
func (c *Claim) Assertions() []HashedURI {
	if c.Version == 1 {
		return append([]HashedURI(nil), c.V1Assertions...)
	}
	return append(append([]HashedURI(nil), c.CreatedAssertions...), c.GatheredAssertions...)
}

// DecodeClaim decodes v2 claim CBOR and checks its required fields. The
// returned claim keeps b as Raw.
func DecodeClaim(b []byte) (*Claim, error) {
	var c Claim
	if err := cbormode.Dec.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("manifest: %w: %w", ErrMalformedClaim, err)
	}
	var missing []string
	if c.InstanceID == "" {
		missing = append(missing, "instanceID")
	}
	if c.ClaimGeneratorInfo.Name() == "" {
		missing = append(missing, "claim_generator_info.name")
	}
	if c.Signature == "" {
		missing = append(missing, "signature")
	}
	if len(c.CreatedAssertions) == 0 {
		missing = append(missing, "created_assertions")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("manifest: %w: missing %v", ErrMalformedClaim, missing)
	}
	for _, h := range c.Assertions() {
		if h.URL == "" || len(h.Hash) == 0 {
			return nil, fmt.Errorf("manifest: %w: assertion reference without url or hash", ErrMalformedClaim)
		}
	}
	c.Raw = b
	c.Version = 2
	return &c, nil
}

// claimV1 is the C2PA 1.x claim map (label c2pa.claim).
type claimV1 struct {
	ClaimGenerator      string          `cbor:"claim_generator"`
	ClaimGeneratorHints map[string]any  `cbor:"claim_generator_hints"`
	ClaimGeneratorInfo  []GeneratorInfo `cbor:"claim_generator_info"`
	Signature           string          `cbor:"signature"`
	Assertions          []HashedURI     `cbor:"assertions"`
	Format              string          `cbor:"dc:format"`
	InstanceID          string          `cbor:"instanceID"`
	Title               string          `cbor:"dc:title"`
	RedactedAssertions  []string        `cbor:"redacted_assertions"`
	Alg                 string          `cbor:"alg"`
	AlgSoft             string          `cbor:"alg_soft"`
	Metadata            map[string]any  `cbor:"metadata"`
}

// v1Fields are the keys a v1 claim may have; c2pa-rs rejects any other.
var v1Fields = []string{
	"claim_generator", "claim_generator_hints", "claim_generator_info", "signature",
	"assertions", "dc:format", "instanceID", "dc:title", "redacted_assertions",
	"alg", "alg_soft", "metadata",
}

// v1Required are the keys a v1 claim must have (c2pa-rs Claim::from_value).
var v1Required = []string{"claim_generator", "signature", "assertions", "dc:format", "instanceID"}

// DecodeClaimV1 decodes C2PA 1.x claim CBOR (label c2pa.claim) the way
// c2pa-rs does: only v1 keys are allowed, and claim_generator, signature,
// assertions, dc:format and instanceID are required. The returned claim has
// Version 1 and keeps b as Raw.
func DecodeClaimV1(b []byte) (*Claim, error) {
	var keys map[string]cbor.RawMessage
	if err := cbormode.Dec.Unmarshal(b, &keys); err != nil {
		return nil, fmt.Errorf("manifest: %w: %w", ErrMalformedClaim, err)
	}
	for k := range keys {
		if !slices.Contains(v1Fields, k) {
			return nil, fmt.Errorf("manifest: %w: unknown v1 claim field %q", ErrMalformedClaim, k)
		}
	}
	var missing []string
	for _, k := range v1Required {
		if _, ok := keys[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("manifest: %w: missing %v", ErrMalformedClaim, missing)
	}
	var v claimV1
	if err := cbormode.Dec.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("manifest: %w: %w", ErrMalformedClaim, err)
	}
	for _, h := range v.Assertions {
		if h.URL == "" || len(h.Hash) == 0 {
			return nil, fmt.Errorf("manifest: %w: assertion reference without url or hash", ErrMalformedClaim)
		}
	}
	c := &Claim{
		Version:             1,
		InstanceID:          v.InstanceID,
		Signature:           v.Signature,
		RedactedAssertions:  v.RedactedAssertions,
		Title:               v.Title,
		Alg:                 v.Alg,
		AlgSoft:             v.AlgSoft,
		Metadata:            v.Metadata,
		ClaimGenerator:      v.ClaimGenerator,
		GeneratorInfoV1:     v.ClaimGeneratorInfo,
		ClaimGeneratorHints: v.ClaimGeneratorHints,
		Format:              v.Format,
		V1Assertions:        v.Assertions,
		ClaimGeneratorInfo:  GeneratorInfo{"name": v.ClaimGenerator},
		Raw:                 b,
	}
	if len(v.ClaimGeneratorInfo) > 0 {
		c.ClaimGeneratorInfo = v.ClaimGeneratorInfo[0]
	}
	return c, nil
}

// Encode returns the core deterministic CBOR encoding of c as a v2 claim,
// for the write path. Raw and the v1 fields are ignored.
func (c *Claim) Encode() ([]byte, error) {
	return cbormode.Enc.Marshal(c)
}
