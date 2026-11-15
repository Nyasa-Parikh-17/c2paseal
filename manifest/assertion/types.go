package assertion

import (
	"bytes"
	"errors"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/fxamacker/cbor/v2"
)

// Actions is a c2pa.actions (v1) or c2pa.actions.v2 assertion. Fields not
// modelled here remain in the assertion's original bytes.
type Actions struct {
	Actions            []Action         `cbor:"actions" json:"actions"`
	Templates          []map[string]any `cbor:"templates,omitempty" json:"templates,omitempty"`
	AllActionsIncluded *bool            `cbor:"allActionsIncluded,omitempty" json:"allActionsIncluded,omitempty"`
	Metadata           map[string]any   `cbor:"metadata,omitempty" json:"metadata,omitempty"`
}

// Action is one entry of an actions assertion.
type Action struct {
	Action             string           `cbor:"action" json:"action"`
	When               string           `cbor:"when,omitempty" json:"when,omitempty"`
	SoftwareAgent      any              `cbor:"softwareAgent,omitempty" json:"softwareAgent,omitempty"` // v2: generator-info map; v1: string
	SoftwareAgentIndex *uint64          `cbor:"softwareAgentIndex,omitempty" json:"softwareAgentIndex,omitempty"`
	DigitalSourceType  string           `cbor:"digitalSourceType,omitempty" json:"digitalSourceType,omitempty"`
	Changes            []map[string]any `cbor:"changes,omitempty" json:"changes,omitempty"`
	Related            []map[string]any `cbor:"related,omitempty" json:"related,omitempty"`
	Reason             string           `cbor:"reason,omitempty" json:"reason,omitempty"`
	Description        string           `cbor:"description,omitempty" json:"description,omitempty"`
	InstanceID         string           `cbor:"instanceId,omitempty" json:"instanceId,omitempty"` // v1 only
	Parameters         map[string]any   `cbor:"parameters,omitempty" json:"parameters,omitempty"`
}

// DataHash is a c2pa.hash.data hard-binding assertion.
type DataHash struct {
	Exclusions []Exclusion `cbor:"exclusions,omitempty" json:"exclusions,omitempty"`
	Name       string      `cbor:"name,omitempty" json:"name,omitempty"`
	Alg        string      `cbor:"alg,omitempty" json:"alg,omitempty"` // empty: inherit the claim's alg
	Hash       []byte      `cbor:"hash" json:"hash"`
	Pad        []byte      `cbor:"pad" json:"pad"`
	Pad2       []byte      `cbor:"pad2,omitempty" json:"pad2,omitempty"`
	URL        string      `cbor:"url,omitempty" json:"url,omitempty"`
}

// BMFFHash is a c2pa.hash.bmff hard-binding assertion (ISO BMFF files such
// as HEIC and AVIF). Field names and JSON follow c2pa-rs.
type BMFFHash struct {
	Exclusions []BMFFExclusion `cbor:"exclusions" json:"exclusions"`
	Alg        string          `cbor:"alg,omitempty" json:"alg,omitempty"` // empty: inherit the claim's alg
	Hash       []byte          `cbor:"hash,omitempty" json:"hash,omitempty"`
	// Merkle holds the per-chunk hashes of fragmented files, kept as CBOR;
	// verifying them is not supported.
	Merkle cbor.RawMessage `cbor:"merkle,omitempty" json:"-"`
	Name   string          `cbor:"name,omitempty" json:"name,omitempty"`
	URL    string          `cbor:"url,omitempty" json:"url,omitempty"` // deprecated remote hash
}

// SoftBinding is a c2pa.soft-binding assertion: a value computed from the
// content (a watermark or fingerprint) that can find the manifest again when
// it has been stripped. Field names follow C2PA 2.4 and c2pa-rs.
type SoftBinding struct {
	// Alg names the algorithm, from the C2PA soft binding algorithm list or
	// an entity-specific name.
	Alg       string             `cbor:"alg,omitempty" json:"alg,omitempty"`
	Blocks    []SoftBindingBlock `cbor:"blocks" json:"blocks"`
	Name      string             `cbor:"name,omitempty" json:"name,omitempty"`
	AlgParams string             `cbor:"alg-params,omitempty" json:"alg-params,omitempty"`
	Pad       []byte             `cbor:"pad" json:"pad"`
	Pad2      []byte             `cbor:"pad2,omitempty" json:"pad2,omitempty"`
}

// SoftBindingBlock is one soft binding value and where it applies.
type SoftBindingBlock struct {
	Scope SoftBindingScope `cbor:"scope" json:"scope"`
	// Value is in the algorithm's own format.
	Value string `cbor:"value" json:"value"`
}

// SoftBindingScope limits a block to a time span or region; empty means the
// whole asset. A region is kept as CBOR.
type SoftBindingScope struct {
	Timespan *SoftBindingTimespan `cbor:"timespan,omitempty" json:"timespan,omitempty"`
	Region   cbor.RawMessage      `cbor:"region,omitempty" json:"-"`
}

// SoftBindingTimespan is a time span in a temporal asset.
type SoftBindingTimespan struct {
	Start uint64 `cbor:"start" json:"start"`
	End   uint64 `cbor:"end" json:"end"`
}

// BMFFExclusion selects boxes left out of a c2pa.hash.bmff hash.
type BMFFExclusion struct {
	XPath   string       `cbor:"xpath" json:"xpath"`
	Length  *uint64      `cbor:"length,omitempty" json:"length,omitempty"`
	Data    []BMFFData   `cbor:"data,omitempty" json:"data,omitempty"`
	Subset  []BMFFSubset `cbor:"subset,omitempty" json:"subset,omitempty"`
	Version *uint8       `cbor:"version,omitempty" json:"version,omitempty"`
	Flags   []byte       `cbor:"flags,omitempty" json:"flags,omitempty"`
	Exact   *bool        `cbor:"exact,omitempty" json:"exact,omitempty"`
}

// BMFFData requires Value at Offset from the start of the box.
type BMFFData struct {
	Offset uint64 `cbor:"offset" json:"offset"`
	Value  []byte `cbor:"value" json:"value"`
}

// BMFFSubset is a range inside a box; Length 0 means to its end.
type BMFFSubset struct {
	Offset uint64 `cbor:"offset" json:"offset"`
	Length uint64 `cbor:"length" json:"length"`
}

// Exclusion is a byte range left out of the hard-binding hash.
type Exclusion struct {
	Start  uint64 `cbor:"start" json:"start"`
	Length uint64 `cbor:"length" json:"length"`
}

// CreativeWork is a stds.schema-org.CreativeWork assertion: schema.org
// JSON-LD, stored in a JSON box (or, less often, CBOR).
type CreativeWork map[string]any

// Thumbnail is a claim or ingredient thumbnail, stored as a JUMBF embedded
// file (bfdb description + bidb data).
type Thumbnail struct {
	Format string // media type from the bfdb box, e.g. "image/jpeg"
	Data   []byte // image bytes; shares memory with the parsed store
}

// decodeThumbnail reads the media type from the bfdb box (toggles byte, then
// a NUL-terminated media type; an optional file name may follow).
func decodeThumbnail(box *jumbf.Box) (*Thumbnail, error) {
	c := box.Contents()
	if len(c) != 2 || c[0].Type != "bfdb" || c[1].Type != "bidb" {
		return nil, errors.New("thumbnail is not a bfdb + bidb embedded file")
	}
	p := c[0].Payload
	if len(p) < 2 {
		return nil, errors.New("bfdb box too short")
	}
	end := bytes.IndexByte(p[1:], 0)
	if end < 0 {
		return nil, errors.New("bfdb media type has no NUL terminator")
	}
	return &Thumbnail{Format: string(p[1 : 1+end]), Data: c[1].Payload}, nil
}
