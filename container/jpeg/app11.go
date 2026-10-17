package jpeg

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
)

// Store is a C2PA manifest store read from a JPEG.
type Store struct {
	Root     *jumbf.Box // parsed manifest store superbox
	JUMBF    []byte     // reassembled store bytes; Root shares this memory
	Segments []Segment  // the APP11 segments carrying the store, in file order
}

// app11Box is one JPEG XT APP11 segment: CI "JP", box instance En, sequence
// number Z, then the box's LBox/TBox[/XLBox] (repeated in every segment)
// and a slice of the box payload.
type app11Box struct {
	seg  Segment
	en   uint16
	z    uint32
	hdr  []byte // LBox, TBox and XLBox if present
	data []byte
}

// parseAPP11 decodes the JPEG XT header of an APP11 segment. ok is false for
// APP11 segments that are not JPEG XT boxes.
func parseAPP11(b []byte, s Segment) (box app11Box, ok bool, err error) {
	p := s.Payload(b)
	if len(p) < 2 || string(p[:2]) != "JP" {
		return app11Box{}, false, nil
	}
	const fixed = 2 + 2 + 4 + 8 // CI, En, Z, LBox+TBox
	if len(p) < fixed {
		return app11Box{}, true, fmt.Errorf("jpeg: %w: APP11 at offset %d too short for a JPEG XT header", ErrBadSegment, s.Offset)
	}
	box = app11Box{seg: s, en: binary.BigEndian.Uint16(p[2:]), z: binary.BigEndian.Uint32(p[4:])}
	hdrLen := 8
	if binary.BigEndian.Uint32(p[8:]) == 1 {
		hdrLen = 16
		if len(p) < 8+hdrLen {
			return app11Box{}, true, fmt.Errorf("jpeg: %w: APP11 at offset %d too short for XLBox", ErrBadSegment, s.Offset)
		}
	}
	box.hdr = p[8 : 8+hdrLen]
	box.data = p[8+hdrLen:]
	return box, true, nil
}

// Extract finds the C2PA manifest store in a JPEG, reassembles it from its
// APP11 segments and parses it. It returns ErrNoManifest if there is none.
func Extract(b []byte) (*Store, error) {
	segs, err := Segments(b)
	if err != nil {
		return nil, err
	}
	g, err := findStore(b, segs)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, fmt.Errorf("jpeg: %w", ErrNoManifest)
	}
	return assemble(g)
}

// findStore returns the APP11 segments of the C2PA box instance, or nil if
// there is none.
func findStore(b []byte, segs []Segment) ([]app11Box, error) {
	groups := map[uint16][]app11Box{}
	var order []uint16
	for _, s := range segs {
		if s.Marker != APP11 {
			continue
		}
		box, ok, err := parseAPP11(b, s)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if _, seen := groups[box.en]; !seen {
			order = append(order, box.en)
		}
		groups[box.en] = append(groups[box.en], box)
	}

	var store []app11Box
	for _, en := range order {
		if g := groups[en]; isC2PA(g) {
			if store != nil {
				return nil, fmt.Errorf("jpeg: %w", ErrMultipleStores)
			}
			store = g
		}
	}
	return store, nil
}

// isC2PA reports whether a box instance is a C2PA manifest store: a jumb
// superbox whose description box is labelled "c2pa". It looks at the first
// segment only, so a store with broken inner boxes is still recognised.
func isC2PA(g []app11Box) bool {
	first := slices.MinFunc(g, func(a, b app11Box) int { return cmp.Compare(a.z, b.z) })
	if string(first.hdr[4:8]) != jumbf.TypeSuperbox {
		return false
	}
	// jumd box: LBox, TBox, 16-byte content type, toggles, label.
	d := first.data
	return len(d) >= 8+17+5 && string(d[4:8]) == jumbf.TypeDescription &&
		d[8+16]&jumbf.ToggleLabel != 0 && string(d[8+17:8+17+5]) == "c2pa\x00"
}

// assemble joins one box instance's segments in sequence order and parses
// the result. The box header appears once, followed by every segment's data.
func assemble(g []app11Box) (*Store, error) {
	sorted := slices.SortedFunc(slices.Values(g), func(a, b app11Box) int { return cmp.Compare(a.z, b.z) })
	hdr := sorted[0].hdr
	size := 0
	for i, box := range sorted {
		if box.z != uint32(i+1) {
			return nil, fmt.Errorf("jpeg: %w: APP11 box instance %d: sequence number %d, want %d",
				ErrBadSegment, box.en, box.z, i+1)
		}
		if !bytes.Equal(box.hdr, hdr) {
			return nil, fmt.Errorf("jpeg: %w: APP11 at offset %d repeats a different box header",
				ErrBadSegment, box.seg.Offset)
		}
		size += len(box.data)
	}

	out := make([]byte, 0, len(hdr)+size)
	out = append(out, hdr...)
	for _, box := range sorted {
		out = append(out, box.data...)
	}
	if want, ok := boxLength(hdr); ok && want != uint64(len(out)) {
		return nil, fmt.Errorf("jpeg: %w: manifest store box declares %d bytes, APP11 segments hold %d",
			ErrTruncated, want, len(out))
	}
	root, err := jumbf.Parse(out)
	if err != nil {
		return nil, fmt.Errorf("jpeg: manifest store: %w", err)
	}

	st := &Store{Root: root, JUMBF: out}
	for _, box := range g {
		st.Segments = append(st.Segments, box.seg)
	}
	slices.SortFunc(st.Segments, func(a, b Segment) int { return cmp.Compare(a.Offset, b.Offset) })
	return st, nil
}

// boxLength returns the total length a box header declares. ok is false for
// LBox 0 (box runs to the end of its container), which declares no length.
func boxLength(hdr []byte) (n uint64, ok bool) {
	switch l := binary.BigEndian.Uint32(hdr); l {
	case 0:
		return 0, false
	case 1:
		return binary.BigEndian.Uint64(hdr[8:]), true
	default:
		return uint64(l), true
	}
}
