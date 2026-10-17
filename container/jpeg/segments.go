package jpeg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Marker codes used by this package.
const (
	SOI   = 0xD8
	EOI   = 0xD9
	SOS   = 0xDA
	APP0  = 0xE0
	APP1  = 0xE1
	APP11 = 0xEB
)

// Errors returned by the parsers. Returned errors wrap one of these.
var (
	ErrNotJPEG        = errors.New("not a JPEG (no SOI marker)")
	ErrTruncated      = errors.New("truncated")
	ErrBadSegment     = errors.New("malformed segment")
	ErrNoManifest     = errors.New("no C2PA manifest store")
	ErrMultipleStores = errors.New("more than one C2PA manifest store")
)

// Segment is one marker in the header part of a JPEG (SOI up to and
// including the SOS header).
type Segment struct {
	Marker byte // marker code, e.g. 0xEB for APP11
	Offset int  // offset of the 0xFF that starts the marker (after any fill bytes)
	Length int  // total bytes from Offset: 2 for standalone markers, else 2 + the length field
}

// End returns the offset just past the segment.
func (s Segment) End() int { return s.Offset + s.Length }

// Payload returns the segment's bytes after its marker and length field.
func (s Segment) Payload(b []byte) []byte {
	if s.Length <= 4 {
		return nil
	}
	return b[s.Offset+4 : s.End()]
}

// standalone reports whether a marker has no length field.
func standalone(m byte) bool {
	return m == 0x01 || (m >= 0xD0 && m <= 0xD9)
}

// Segments walks the markers from SOI to SOS (or EOI, if it comes first)
// and returns them in file order. Fill bytes (extra 0xFF) are skipped and
// belong to no segment. Entropy-coded data after SOS is not walked.
func Segments(b []byte) ([]Segment, error) {
	if len(b) < 2 || b[0] != 0xFF || b[1] != SOI {
		return nil, fmt.Errorf("jpeg: %w", ErrNotJPEG)
	}
	segs := []Segment{{Marker: SOI, Offset: 0, Length: 2}}
	for i := 2; ; {
		if i >= len(b) {
			return nil, fmt.Errorf("jpeg: %w: no SOS marker before end of data", ErrTruncated)
		}
		if b[i] != 0xFF {
			return nil, fmt.Errorf("jpeg: %w: expected marker at offset %d, found 0x%02X", ErrBadSegment, i, b[i])
		}
		for i+1 < len(b) && b[i+1] == 0xFF {
			i++ // fill byte
		}
		if i+1 >= len(b) {
			return nil, fmt.Errorf("jpeg: %w: marker at offset %d", ErrTruncated, i)
		}
		m := b[i+1]
		if m == 0x00 {
			return nil, fmt.Errorf("jpeg: %w: stuffed byte outside scan data at offset %d", ErrBadSegment, i)
		}
		seg := Segment{Marker: m, Offset: i, Length: 2}
		if !standalone(m) {
			if i+4 > len(b) {
				return nil, fmt.Errorf("jpeg: %w: length of marker 0x%02X at offset %d", ErrTruncated, m, i)
			}
			n := int(binary.BigEndian.Uint16(b[i+2:]))
			if n < 2 {
				return nil, fmt.Errorf("jpeg: %w: marker 0x%02X at offset %d has length %d", ErrBadSegment, m, i, n)
			}
			seg.Length = 2 + n
			if seg.End() > len(b) {
				return nil, fmt.Errorf("jpeg: %w: marker 0x%02X at offset %d needs %d bytes, %d left",
					ErrTruncated, m, i, seg.Length, len(b)-i)
			}
		}
		segs = append(segs, seg)
		if m == SOS || m == EOI {
			return segs, nil
		}
		i = seg.End()
	}
}
