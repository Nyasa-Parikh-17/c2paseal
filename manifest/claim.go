package manifest

import (
	"errors"
	"fmt"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
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

// Claim is a C2PA v2 claim (label c2pa.claim.v2). Raw holds the original
// CBOR, which is what the signature covers; never re-encode a decoded claim
// to verify it.
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

	Raw []byte `cbor:"-" json:"-"`
}

// Assertions returns the created then the gathered assertion references.
func (c *Claim) Assertions() []HashedURI {
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
	return &c, nil
}

// Encode returns the core deterministic CBOR encoding of c, for the write
// path. Raw is ignored.
func (c *Claim) Encode() ([]byte, error) {
	return cbormode.Enc.Marshal(c)
}
