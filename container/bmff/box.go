// Package bmff reads and writes ISO base media file format (ISO/IEC
// 14496-12) files, such as HEIC and AVIF images, for C2PA: the box tree,
// the C2PA manifest store box, the absolute offsets that move when a box is
// inserted (meta/iloc), and the byte ranges of the c2pa.hash.bmff hard
// binding.
//
// The box tree follows c2pa-rs (sdk/src/asset_handlers/bmff_io.rs,
// build_bmff_tree) so that exclusion paths match the same boxes: the same
// container boxes are descended into, the same "full boxes" have their
// version and flags read, a size-0 box runs to the end of the file, an mdat
// that runs past the end is cut short, and unreadable trailing bytes end
// the walk.
package bmff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// MaxDepth limits box nesting, as c2pa-rs does.
const MaxDepth = 32

var (
	ErrNotBMFF   = errors.New("not an ISO BMFF file")
	ErrTruncated = errors.New("box extends past the end of the file")
	ErrMalformed = errors.New("malformed box")
	ErrTooDeep   = errors.New("boxes nested too deeply")
)

// containers are the box types whose children c2pa-rs walks.
var containers = map[string]bool{
	"moov": true, "trak": true, "mdia": true, "minf": true, "stbl": true, "moof": true,
	"traf": true, "edts": true, "udta": true, "dinf": true, "tref": true, "treg": true,
	"mvex": true, "mfra": true, "meta": true, "schi": true,
}

// fullBoxes are the box types with a version and flags after the header
// (c2pa-rs FULL_BOX_TYPES).
var fullBoxes = map[string]bool{}

func init() {
	for _, t := range []string{
		"pdin", "mvhd", "tkhd", "mdhd", "hdlr", "nmhd", "elng", "stsd", "stdp", "stts", "ctts", "cslg",
		"stss", "stsh", "elst", "dref", "stsz", "stz2", "stsc", "stco", "co64", "padb", "subs",
		"saiz", "saio", "mehd", "trex", "mfhd", "tfhd", "trun", "tfra", "mfro", "tfdt", "leva", "trep",
		"assp", "sbgp", "sgpd", "csgp", "cprt", "tsel", "kind", "meta", "xml ", "bxml", "iloc", "pitm",
		"ipro", "infe", "iinf", "iref", "ipma", "schm", "fiin", "fpar", "fecr", "gitn", "fire", "stri",
		"stsg", "stvi", "csch", "sidx", "ssix", "prft", "srpp", "vmhd", "smhd", "srat", "chnl", "dmix",
		"txtC", "mime", "uri ", "uriI", "hmhd", "sthd", "vvhd", "medc",
	} {
		fullBoxes[t] = true
	}
}

// Box is one box of the tree.
type Box struct {
	Type      string // the FourCC
	Path      string // "/meta/iloc": the types from the top, as c2pa-rs builds it
	Offset    int    // of the box header in the file
	Size      int    // of the whole box, header included
	HeaderLen int    // 8, or 16 with a 64-bit size
	UserType  []byte // the 16-byte extended type of a uuid box
	// HasVersion is set for full boxes (and the C2PA uuid box); Version and
	// Flags are then their values.
	HasVersion bool
	Version    uint8
	Flags      uint32
	Children   []*Box
}

// End is the offset just after the box.
func (b *Box) End() int { return b.Offset + b.Size }

// Tree is a parsed file: its top-level boxes and every box by path, in file
// order.
type Tree struct {
	Top    []*Box
	ByPath map[string][]*Box
}

// IsBMFF reports whether b starts with an ftyp box, the way HEIC, AVIF and
// MP4 files do.
func IsBMFF(b []byte) bool {
	return len(b) >= 12 && string(b[4:8]) == "ftyp" && binary.BigEndian.Uint32(b) >= 12
}

// Brands returns the major brand and the compatible brands of the ftyp box
// at the start of b.
func Brands(b []byte) (major string, compatible []string) {
	if !IsBMFF(b) {
		return "", nil
	}
	n := min(int(binary.BigEndian.Uint32(b)), len(b))
	major = string(b[8:12])
	for i := 16; i+4 <= n; i += 4 {
		compatible = append(compatible, string(b[i:i+4]))
	}
	return major, compatible
}

// Parse builds the box tree of b.
func Parse(b []byte) (*Tree, error) {
	t := &Tree{ByPath: map[string][]*Box{}}
	top, err := t.walk(b, 0, len(b), "", 1)
	if err != nil {
		return nil, err
	}
	t.Top = top
	return t, nil
}

func (t *Tree) walk(b []byte, start, end int, parent string, depth int) ([]*Box, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("bmff: %w", ErrTooDeep)
	}
	var boxes []*Box
	for cur := start; cur < end; {
		if len(b)-cur < 8 {
			break // trailing bytes that are not a box header
		}
		size := uint64(binary.BigEndian.Uint32(b[cur:]))
		typ := string(b[cur+4 : cur+8])
		hdr := 8
		switch size {
		case 1:
			if len(b)-cur < 16 {
				return boxes, nil
			}
			size = binary.BigEndian.Uint64(b[cur+8:])
			hdr = 16
		case 0:
			size = uint64(len(b) - cur) // to the end of the file
		}
		if size == 0 {
			break
		}
		if size < uint64(hdr) {
			return nil, fmt.Errorf("bmff: %q box at offset %d: size %d is smaller than its header: %w", typ, cur, size, ErrMalformed)
		}
		if uint64(cur)+size > uint64(end) {
			if typ != "mdat" {
				return nil, fmt.Errorf("bmff: %q box at offset %d: %w", typ, cur, ErrTruncated)
			}
			size = uint64(end - cur) // an mdat that runs past the end is cut short
		}
		bx := &Box{Type: typ, Path: parent + "/" + typ, Offset: cur, Size: int(size), HeaderLen: hdr}
		body := cur + hdr
		bend := cur + int(size)
		readVF := func(at int) error {
			if bend-at < 4 {
				return fmt.Errorf("bmff: %q box at offset %d: no version and flags: %w", typ, cur, ErrMalformed)
			}
			bx.HasVersion = true
			bx.Version = b[at]
			bx.Flags = uint32(b[at+1])<<16 | uint32(b[at+2])<<8 | uint32(b[at+3])
			return nil
		}
		switch {
		case typ == "uuid":
			if bend-body < 16 {
				return nil, fmt.Errorf("bmff: uuid box at offset %d: no extended type: %w", cur, ErrMalformed)
			}
			bx.UserType = b[body : body+16]
			if [16]byte(bx.UserType) == C2PAUUID {
				if err := readVF(body + 16); err != nil {
					return nil, err
				}
			}
		case containers[typ]:
			child := body
			if fullBoxes[typ] && !(typ == "meta" && metaLacksFullBoxHeader(b, body, bend)) {
				if err := readVF(body); err != nil {
					return nil, err
				}
				child += 4
			}
			t.ByPath[bx.Path] = append(t.ByPath[bx.Path], bx)
			kids, err := t.walk(b, child, bend, bx.Path, depth+1)
			if err != nil {
				return nil, err
			}
			bx.Children = kids
			boxes = append(boxes, bx)
			cur = bend
			continue
		case fullBoxes[typ]:
			if err := readVF(body); err != nil {
				return nil, err
			}
		}
		t.ByPath[bx.Path] = append(t.ByPath[bx.Path], bx)
		boxes = append(boxes, bx)
		cur = bend
	}
	return boxes, nil
}

// metaLacksFullBoxHeader detects QuickTime's meta box, written without the
// version and flags a meta FullBox should have: its data starts straight
// with the hdlr child's header.
func metaLacksFullBoxHeader(b []byte, body, end int) bool {
	return end-body >= 8 && string(b[body+4:body+8]) == "hdlr"
}

// TopOffsets returns the offsets of the top-level boxes, sorted.
func (t *Tree) TopOffsets() []int {
	var out []int
	for _, bx := range t.Top {
		out = append(out, bx.Offset)
	}
	slices.Sort(out)
	return out
}

// First returns the first box with the path, or nil.
func (t *Tree) First(path string) *Box {
	if l := t.ByPath[path]; len(l) > 0 {
		return l[0]
	}
	return nil
}
