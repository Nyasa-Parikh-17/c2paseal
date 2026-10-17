package assertion

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/cbormode"
)

// Assertion labels (C2PA 2.4). Instance suffixes such as "__1" are allowed
// on any of them.
const (
	LabelActions        = "c2pa.actions"
	LabelActionsV2      = "c2pa.actions.v2"
	LabelDataHash       = "c2pa.hash.data"
	LabelCreativeWork   = "stds.schema-org.CreativeWork"
	LabelThumbnailClaim = "c2pa.thumbnail.claim" // optionally followed by ".jpeg", ".png", …
	LabelThumbnailIngr  = "c2pa.thumbnail.ingredient"
)

// ErrMalformed wraps every assertion decode error.
var ErrMalformed = errors.New("malformed assertion")

// Assertion is one assertion superbox from a manifest's assertion store.
type Assertion struct {
	Label string     // full label, including any instance suffix
	Box   *jumbf.Box // the assertion superbox, with its original bytes

	// Value is the decoded content for in-scope labels: *Actions, *DataHash,
	// CreativeWork or *Thumbnail. It is nil for other labels, whose content
	// stays available through Box.
	Value any
	// Err is set when an in-scope assertion could not be decoded.
	Err error
}

var instanceSuffix = regexp.MustCompile(`__\d+$`)

// BaseLabel returns label without an instance suffix ("c2pa.actions__2" →
// "c2pa.actions").
func BaseLabel(label string) string {
	return instanceSuffix.ReplaceAllString(label, "")
}

// Decode decodes an assertion superbox. It never fails: problems with an
// in-scope assertion are reported in Assertion.Err.
func Decode(box *jumbf.Box) Assertion {
	a := Assertion{Label: box.Label(), Box: box}
	base := BaseLabel(a.Label)
	var err error
	switch {
	case base == LabelActions || base == LabelActionsV2:
		var v Actions
		if err = decodeCBOR(box, &v); err == nil {
			a.Value = &v
		}
	case base == LabelDataHash:
		var v DataHash
		if err = decodeCBOR(box, &v); err == nil {
			a.Value = &v
		}
	case base == LabelCreativeWork:
		var v CreativeWork
		if err = decodeJSONOrCBOR(box, &v); err == nil {
			a.Value = v
		}
	case isThumbnail(base):
		var v *Thumbnail
		if v, err = decodeThumbnail(box); err == nil {
			a.Value = v
		}
	}
	if err != nil {
		a.Err = fmt.Errorf("assertion %q: %w: %w", a.Label, ErrMalformed, err)
	}
	return a
}

func isThumbnail(base string) bool {
	for _, p := range []string{LabelThumbnailClaim, LabelThumbnailIngr} {
		if base == p || strings.HasPrefix(base, p+".") {
			return true
		}
	}
	return false
}

// content returns the single content box of an assertion superbox.
func content(box *jumbf.Box, types ...string) (*jumbf.Box, error) {
	c := box.Contents()
	if len(c) == 0 {
		return nil, errors.New("no content box")
	}
	for _, t := range types {
		if c[0].Type == t {
			return c[0], nil
		}
	}
	return nil, fmt.Errorf("content box type %q, want %q", c[0].Type, types)
}

func decodeCBOR(box *jumbf.Box, v any) error {
	c, err := content(box, "cbor")
	if err != nil {
		return err
	}
	return cbormode.Dec.Unmarshal(c.Payload, v)
}

func decodeJSONOrCBOR(box *jumbf.Box, v any) error {
	c, err := content(box, "json", "cbor")
	if err != nil {
		return err
	}
	if c.Type == "json" {
		return json.Unmarshal(c.Payload, v)
	}
	return cbormode.Dec.Unmarshal(c.Payload, v)
}
