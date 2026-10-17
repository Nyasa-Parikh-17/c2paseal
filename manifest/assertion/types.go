package assertion

import (
	"bytes"
	"errors"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
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
