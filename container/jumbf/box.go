package jumbf

import (
	"errors"
	"fmt"
	"strings"
)

// Box types with special handling. Every other type is a content box whose
// payload is kept as raw bytes.
const (
	TypeSuperbox    = "jumb"
	TypeDescription = "jumd"
)

// LengthForm records how a box header encoded its length, so Serialize can
// reproduce the original bytes exactly.
type LengthForm uint8

const (
	// Compact is a 4-byte LBox holding the total box length.
	Compact LengthForm = iota
	// Extended is LBox = 1 followed by an 8-byte XLBox.
	Extended
	// ToEnd is LBox = 0: the box runs to the end of its container.
	ToEnd
)

// Toggle bits of a description box (ISO/IEC 19566-5).
const (
	ToggleRequestable = 1 << 0
	ToggleLabel       = 1 << 1
	ToggleID          = 1 << 2
	ToggleHash        = 1 << 3
	TogglePrivate     = 1 << 4
)

// Parse errors. Returned errors wrap one of these with the failing offset.
var (
	ErrTruncated     = errors.New("truncated box")
	ErrBadLength     = errors.New("invalid box length")
	ErrNoDescription = errors.New("superbox does not start with a jumd box")
	ErrTooDeep       = errors.New("boxes nested too deeply")
	ErrTopLevel      = errors.New("input is not exactly one box")
)

// UUID is a 16-byte JUMBF content-type identifier.
type UUID [16]byte

func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// Box is one JUMBF box. Exactly one of Children, Description and Payload is
// used, chosen by Type: "jumb" has Children (the first is always its jumd),
// "jumd" has Description, every other type has Payload.
//
// Boxes returned by Parse share memory with the parsed input; Raw and
// Payload must not be modified unless the input may be.
type Box struct {
	Type string // 4-character TBox
	Form LengthForm

	Children    []*Box
	Description *Description
	Payload     []byte

	// Set by Parse: where the box started in the parsed input, and its
	// original bytes (header and payload). Nil for boxes built in code.
	Offset int
	Raw    []byte
}

// Description is the content of a jumd box. Toggles decides which optional
// fields are present when serialising.
type Description struct {
	ContentType UUID
	Toggles     byte
	Label       string // present if ToggleLabel; stored without its NUL
	ID          uint32 // present if ToggleID
	Hash        []byte // present if ToggleHash; 32 bytes
	Private     *Box   // present if TogglePrivate
	Extra       []byte // bytes after the defined fields, kept for round trips
}

// IsSuperbox reports whether b is a jumb box.
func (b *Box) IsSuperbox() bool { return b.Type == TypeSuperbox }

// Desc returns a superbox's description, or nil if b is not a superbox.
func (b *Box) Desc() *Description {
	if !b.IsSuperbox() || len(b.Children) == 0 {
		return nil
	}
	return b.Children[0].Description
}

// Label returns a superbox's label, or "" if it has none.
func (b *Box) Label() string {
	if d := b.Desc(); d != nil {
		return d.Label
	}
	return ""
}

// Contents returns a superbox's children after its description box.
func (b *Box) Contents() []*Box {
	if !b.IsSuperbox() || len(b.Children) == 0 {
		return nil
	}
	return b.Children[1:]
}

// Child returns the first child superbox with the given label, or nil.
func (b *Box) Child(label string) *Box {
	for _, c := range b.Contents() {
		if c.IsSuperbox() && c.Label() == label {
			return c
		}
	}
	return nil
}

// Find follows a slash-separated label path starting with b's own label,
// e.g. "c2pa/<manifest>/c2pa.assertions/c2pa.hash.data". It returns nil if
// any label along the path is missing.
func (b *Box) Find(path string) *Box {
	labels := strings.Split(path, "/")
	if b.Label() == "" || labels[0] != b.Label() {
		return nil
	}
	cur := b
	for _, l := range labels[1:] {
		if cur = cur.Child(l); cur == nil {
			return nil
		}
	}
	return cur
}
