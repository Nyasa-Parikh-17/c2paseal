package bmff

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"slices"
)

// Exclusion is one entry of a c2pa.hash.bmff assertion's exclusions: the
// boxes at XPath, narrowed by the optional fields, are left out of the
// hash (whole, or only the Subset ranges).
type Exclusion struct {
	XPath   string
	Length  *uint64 // only boxes of this size
	Data    []DataMatch
	Subset  []Subset
	Version *uint8
	Flags   []byte // 3 bytes
	Exact   *bool  // flags must equal (default) or only be a subset
}

// DataMatch requires Value at Offset from the box start.
type DataMatch struct {
	Offset uint64
	Value  []byte
}

// Subset is a range inside a box; Length 0 means to the end of the box.
type Subset struct {
	Offset, Length uint64
}

// DefaultExclusions are the exclusions c2pa-rs writes when it signs an ISO
// BMFF file (BmffHash::set_default_exclusions): the C2PA box, ftyp, mfra,
// free and skip.
func DefaultExclusions() []Exclusion {
	return []Exclusion{
		{XPath: "/uuid", Data: []DataMatch{{Offset: 8, Value: C2PAUUID[:]}}},
		{XPath: "/ftyp"},
		{XPath: "/mfra"},
		{XPath: "/free"},
		{XPath: "/skip"},
	}
}

// ErrBadExclusion is returned when exclusions do not fit the file: a data
// match or a range past its end, or nothing left to hash.
var ErrBadExclusion = errors.New("exclusion does not fit the file")

// hashRange is a byte range to leave out, or with marker set, a top-level
// box offset whose 8-byte big-endian value is hashed (version 2 and 3).
type hashRange struct {
	start, length uint64
	marker        bool
}

// exclusionRanges turns the exclusions into byte ranges, as c2pa-rs's
// bmff_to_jumbf_exclusions does. With offsets (hash versions 2 and 3) it
// adds a marker for every top-level box that is not wholly excluded.
func exclusionRanges(b []byte, t *Tree, excl []Exclusion, offsets bool) ([]hashRange, error) {
	tl := t.TopOffsets()
	var out []hashRange
	for _, e := range excl {
		for _, bx := range t.ByPath[e.XPath] {
			start, length := uint64(bx.Offset), uint64(bx.Size)
			if e.Length != nil && *e.Length != length {
				continue
			}
			if e.Version != nil && bx.HasVersion && *e.Version != bx.Version {
				continue
			}
			if e.Flags != nil && bx.HasVersion {
				var fb [4]byte
				if len(e.Flags) >= 3 {
					copy(fb[:3], e.Flags[:3])
				}
				want := binary.BigEndian.Uint32(fb[:])
				if e.Exact == nil || *e.Exact {
					if want != bx.Flags {
						continue
					}
				} else if want|bx.Flags != want {
					continue
				}
			}
			match := true
			for _, d := range e.Data {
				p := start + d.Offset
				if p < start || p+uint64(len(d.Value)) > uint64(len(b)) {
					return nil, fmt.Errorf("bmff: exclusion %s: data match at %d past the end of the file: %w", e.XPath, p, ErrBadExclusion)
				}
				if !bytes.Equal(b[p:p+uint64(len(d.Value))], d.Value) {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			if e.Subset != nil {
				for _, s := range e.Subset {
					if s.Offset > length {
						continue
					}
					n := length - s.Offset
					if s.Length != 0 {
						n = min(s.Length, n)
					}
					out = append(out, hashRange{start: start + s.Offset, length: n})
				}
				continue
			}
			out = append(out, hashRange{start: start, length: length})
			if i := slices.Index(tl, bx.Offset); i >= 0 {
				tl = slices.Delete(tl, i, i+1)
			}
		}
	}
	if offsets {
		for _, o := range tl {
			out = append(out, hashRange{start: uint64(o), length: 1, marker: true})
		}
	}
	return out, nil
}

// span is an inclusive byte range to hash; with marker set it stands for
// the 8-byte big-endian value of start instead.
type span struct {
	start, end uint64
	marker     bool
}

// Digest computes a c2pa.hash.bmff hash of b with h, the way c2pa-rs's
// hash_stream_by_alg does: the file minus the excluded ranges, with (for
// versions 2 and 3, offsets set) the 8-byte offset of each remaining
// top-level box hashed just before that box's bytes.
func Digest(h hash.Hash, b []byte, excl []Exclusion, offsets bool) ([]byte, error) {
	t, err := Parse(b)
	if err != nil {
		return nil, err
	}
	ranges, err := exclusionRanges(b, t, excl, offsets)
	if err != nil {
		return nil, err
	}
	spans, err := spansToHash(uint64(len(b)), ranges)
	if err != nil {
		return nil, err
	}
	var off [8]byte
	for _, s := range spans {
		if s.marker {
			binary.BigEndian.PutUint64(off[:], s.start)
			h.Write(off[:])
			continue
		}
		h.Write(b[s.start : s.end+1])
	}
	return h.Sum(nil), nil
}

// spansToHash builds the ordered list of what to hash from the exclusion
// ranges and markers (c2pa-rs hash_stream_by_alg_with_progress_impl, the
// is_exclusion branch).
func spansToHash(size uint64, hr []hashRange) ([]span, error) {
	if size < 1 {
		return nil, fmt.Errorf("bmff: no data to hash: %w", ErrBadExclusion)
	}
	last := size - 1
	if len(hr) == 0 {
		return []span{{start: 0, end: last}}, nil
	}
	slices.SortStableFunc(hr, func(a, b hashRange) int { return cmp.Compare(a.start, b.start) })
	if end := hr[len(hr)-1].start + hr[len(hr)-1].length; end < hr[len(hr)-1].start || end > size {
		return nil, fmt.Errorf("bmff: exclusion range past the end of the file: %w", ErrBadExclusion)
	}
	// The file as one range, minus every exclusion.
	incl := []span{{start: 0, end: last}}
	var markers []uint64
	for _, r := range hr {
		if r.marker {
			markers = append(markers, r.start)
			continue
		}
		if r.length == 0 {
			continue
		}
		incl = subtract(incl, r.start, r.start+r.length-1)
	}
	if len(markers) == 0 {
		return incl, nil
	}
	slices.Sort(markers)
	var out []span
	for _, r := range incl {
		cur := r
		for _, os := range markers {
			if os < cur.start || os > cur.end {
				continue
			}
			if cur.start == os {
				out = append(out, span{start: os, end: os, marker: true})
			} else {
				out = append(out, span{start: cur.start, end: os - 1}, span{start: os, end: os, marker: true})
				cur = span{start: os, end: cur.end}
			}
		}
		out = append(out, cur)
	}
	// Markers inside excluded parts (because of subsets) still count when
	// they fall between the first and the last range.
	first, lastEnd := uint64(0), last
	if len(out) > 0 {
		first, lastEnd = out[0].start, out[len(out)-1].end
	}
	for _, os := range markers {
		in := false
		for _, s := range out {
			if os >= s.start && os <= s.end {
				in = true
				break
			}
		}
		if !in && os > first && os < lastEnd {
			out = append(out, span{start: os, end: os, marker: true})
		}
	}
	slices.SortStableFunc(out, func(a, b span) int { return cmp.Compare(a.start, b.start) })
	return out, nil
}

// subtract removes [s, e] from the sorted, disjoint inclusive ranges.
func subtract(ranges []span, s, e uint64) []span {
	var out []span
	for _, r := range ranges {
		if e < r.start || s > r.end {
			out = append(out, r)
			continue
		}
		if s > r.start {
			out = append(out, span{start: r.start, end: s - 1})
		}
		if e < r.end {
			out = append(out, span{start: e + 1, end: r.end})
		}
	}
	return out
}
