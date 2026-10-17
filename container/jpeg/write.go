package jpeg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Layout constants. They match c2pa-rs (asset_handlers/jpeg_io.rs) so that
// Insert(Strip(f), Extract(f)) reproduces a c2patool-signed file exactly.
const (
	// MaxChunk is the number of manifest store bytes per APP11 segment. The
	// first segment carries the store's own box header inside its chunk;
	// later segments repeat that header in front of their chunk.
	MaxChunk = 64000
	// BoxInstance is the JPEG XT box instance number (En) Insert writes.
	BoxInstance = 0x0211
	// segOverhead is marker + Le + CI + En + Z.
	segOverhead = 2 + 2 + 2 + 2 + 4
)

// ErrHasManifest is returned by Insert when the JPEG already carries a C2PA
// manifest store. Strip it first.
var ErrHasManifest = errors.New("JPEG already has a C2PA manifest store")

// SegmentCount returns how many APP11 segments Insert uses for a manifest
// store of storeLen bytes.
func SegmentCount(storeLen int) int {
	if storeLen <= 0 {
		return 0
	}
	return (storeLen + MaxChunk - 1) / MaxChunk
}

// InsertedSize returns how many bytes Insert adds to a JPEG for a manifest
// store of storeLen bytes whose box header is hdrLen bytes (8, or 16 with an
// XLBox).
func InsertedSize(storeLen, hdrLen int) int {
	n := SegmentCount(storeLen)
	if n == 0 {
		return 0
	}
	return storeLen + n*segOverhead + (n-1)*hdrLen
}

// Strip returns a copy of b without the APP11 segments of its C2PA manifest
// store. A JPEG without a store is returned unchanged (as a copy). The store
// does not need to be valid, only recognisable.
func Strip(b []byte) ([]byte, error) {
	segs, err := Segments(b)
	if err != nil {
		return nil, err
	}
	g, err := findStore(b, segs)
	if err != nil {
		return nil, err
	}
	remove := make([]Segment, len(g))
	for i, box := range g {
		remove[i] = box.seg
	}
	slices.SortFunc(remove, func(a, b Segment) int { return a.Offset - b.Offset })

	out := make([]byte, 0, len(b))
	prev := 0
	for _, s := range remove {
		out = append(out, b[prev:s.Offset]...)
		prev = s.End()
	}
	return append(out, b[prev:]...), nil
}

// Insert returns a copy of b with store (a serialised JUMBF manifest store)
// embedded as JPEG XT APP11 segments, and the segments' positions in the
// result. The segments go after the last APP0 segment if there is one,
// otherwise straight after SOI; this is where c2pa-rs puts them.
func Insert(b, store []byte) ([]byte, []Segment, error) {
	segs, err := Segments(b)
	if err != nil {
		return nil, nil, err
	}
	if g, err := findStore(b, segs); err != nil {
		return nil, nil, err
	} else if g != nil {
		return nil, nil, fmt.Errorf("jpeg: %w", ErrHasManifest)
	}
	hdrLen, err := storeHeaderLen(store)
	if err != nil {
		return nil, nil, err
	}

	at := 2 // after SOI
	for _, s := range segs {
		if s.Marker == APP0 {
			at = s.End()
		}
	}

	n := SegmentCount(len(store))
	out := make([]byte, 0, len(b)+InsertedSize(len(store), hdrLen))
	out = append(out, b[:at]...)
	placed := make([]Segment, 0, n)
	for z := 1; z <= n; z++ {
		chunk := store[(z-1)*MaxChunk : min(z*MaxChunk, len(store))]
		le := segOverhead - 2 + len(chunk)
		if z > 1 {
			le += hdrLen
		}
		placed = append(placed, Segment{Marker: APP11, Offset: len(out), Length: 2 + le})
		out = append(out, 0xFF, APP11)
		out = binary.BigEndian.AppendUint16(out, uint16(le))
		out = append(out, 'J', 'P')
		out = binary.BigEndian.AppendUint16(out, BoxInstance)
		out = binary.BigEndian.AppendUint32(out, uint32(z))
		if z > 1 {
			out = append(out, store[:hdrLen]...)
		}
		out = append(out, chunk...)
	}
	return append(out, b[at:]...), placed, nil
}

// storeHeaderLen checks that store starts with a jumb box header and returns
// the header's length.
func storeHeaderLen(store []byte) (int, error) {
	if len(store) < 8 || string(store[4:8]) != "jumb" {
		return 0, fmt.Errorf("jpeg: %w: manifest store is not a jumb box", ErrBadSegment)
	}
	if binary.BigEndian.Uint32(store) == 1 {
		if len(store) < 16 {
			return 0, fmt.Errorf("jpeg: %w: manifest store XLBox cut short", ErrBadSegment)
		}
		return 16, nil
	}
	return 8, nil
}
