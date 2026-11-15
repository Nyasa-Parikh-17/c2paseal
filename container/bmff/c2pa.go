package bmff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
)

// C2PAUUID is the extended type of the C2PA manifest store box
// (d8fec3d6-1b0e-483c-9297-5828877ec481).
var C2PAUUID = [16]byte{0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81}

// PurposeManifest is the purpose of a box holding a whole manifest store.
const PurposeManifest = "manifest"

var (
	ErrNoManifest     = errors.New("no C2PA manifest box")
	ErrMultipleStores = errors.New("more than one C2PA manifest box")
	ErrHasManifest    = errors.New("file already has a C2PA manifest box")
	ErrNoFtyp         = errors.New("no ftyp box")
	ErrOutOfRange     = errors.New("write outside the inserted manifest store")
	ErrUnsupported    = errors.New("unsupported C2PA box")
)

// Store is a manifest store read from a C2PA box.
type Store struct {
	Root    *jumbf.Box // parsed manifest store; shares memory with the input
	JUMBF   []byte     // the store bytes
	Box     *Box       // the C2PA uuid box
	Purpose string
	// DataOffset is where JUMBF starts in the file.
	DataOffset int
}

// c2paBox reads a C2PA uuid box's purpose and returns where its store
// starts. The layout is: header, 16-byte extended type, version and flags,
// the purpose as a NUL-terminated string, then for "manifest" an 8-byte
// Merkle offset followed by the store.
func c2paBox(b []byte, bx *Box) (purpose string, dataOff int, err error) {
	p := bx.Offset + bx.HeaderLen + 16 + 4
	nul := bytes.IndexByte(b[p:bx.End()], 0)
	if nul < 0 {
		return "", 0, fmt.Errorf("bmff: C2PA box at offset %d: purpose without a NUL: %w", bx.Offset, ErrMalformed)
	}
	purpose = string(b[p : p+nul])
	dataOff = p + nul + 1
	if purpose == PurposeManifest || purpose == "original" || purpose == "update" {
		dataOff += 8 // Merkle offset
	}
	if dataOff > bx.End() {
		return "", 0, fmt.Errorf("bmff: C2PA box at offset %d: %w", bx.Offset, ErrTruncated)
	}
	return purpose, dataOff, nil
}

// manifestBox returns the top-level C2PA box with purpose "manifest".
func manifestBox(b []byte, t *Tree) (*Box, string, int, error) {
	var found *Box
	var purpose string
	var data int
	for _, bx := range t.Top {
		if bx.Type != "uuid" || [16]byte(bx.UserType) != C2PAUUID {
			continue
		}
		p, d, err := c2paBox(b, bx)
		if err != nil {
			return nil, "", 0, err
		}
		switch p {
		case PurposeManifest:
		case "original", "update":
			return nil, "", 0, fmt.Errorf("bmff: %w: update manifests (purpose %q)", ErrUnsupported, p)
		default:
			continue // Merkle boxes and other purposes are not the store
		}
		if found != nil {
			return nil, "", 0, fmt.Errorf("bmff: %w", ErrMultipleStores)
		}
		found, purpose, data = bx, p, d
	}
	return found, purpose, data, nil
}

// Extract reads and parses the manifest store from the C2PA box. It returns
// ErrNoManifest if there is none.
func Extract(b []byte) (*Store, error) {
	t, err := Parse(b)
	if err != nil {
		return nil, err
	}
	bx, purpose, data, err := manifestBox(b, t)
	if err != nil {
		return nil, err
	}
	if bx == nil {
		return nil, fmt.Errorf("bmff: %w", ErrNoManifest)
	}
	store := b[data:bx.End()]
	root, err := jumbf.Parse(store)
	if err != nil {
		return nil, fmt.Errorf("bmff: manifest store: %w", err)
	}
	return &Store{Root: root, JUMBF: store, Box: bx, Purpose: purpose, DataOffset: data}, nil
}

// InsertedSize returns the size of the C2PA box Insert adds for a store of
// storeLen bytes.
func InsertedSize(storeLen int) int {
	n := 8 + 16 + 4 + len(PurposeManifest) + 1 + 8 + storeLen
	if n > math.MaxUint32 {
		n += 8
	}
	return n
}

// Insert returns a copy of b with store in a C2PA box straight after ftyp
// (where c2pa-rs puts it), the absolute offsets in meta/iloc moved by the
// box's size, the new box and where the store starts.
func Insert(b, store []byte) ([]byte, *Box, int, error) {
	t, err := Parse(b)
	if err != nil {
		return nil, nil, 0, err
	}
	if bx, _, _, err := manifestBox(b, t); err != nil {
		return nil, nil, 0, err
	} else if bx != nil {
		return nil, nil, 0, fmt.Errorf("bmff: %w", ErrHasManifest)
	}
	ftyp := t.First("/ftyp")
	if ftyp == nil {
		return nil, nil, 0, fmt.Errorf("bmff: %w", ErrNoFtyp)
	}
	if ftyp.HeaderLen == 8 && binary.BigEndian.Uint32(b[ftyp.Offset:]) == 0 {
		// Size 0: ftyp runs to the end of the file, so a box after it would
		// be read as part of ftyp.
		return nil, nil, 0, fmt.Errorf("bmff: ftyp box at offset %d extends to the end of the file: %w", ftyp.Offset, ErrMalformed)
	}
	at := ftyp.End()
	size := InsertedSize(len(store))
	box := make([]byte, 0, size)
	hdr := 8
	if size > math.MaxUint32 {
		box = binary.BigEndian.AppendUint32(box, 1)
		box = append(box, "uuid"...)
		box = binary.BigEndian.AppendUint64(box, uint64(size))
		hdr = 16
	} else {
		box = binary.BigEndian.AppendUint32(box, uint32(size))
		box = append(box, "uuid"...)
	}
	box = append(box, C2PAUUID[:]...)
	box = append(box, 0, 0, 0, 0) // version, flags
	box = append(box, PurposeManifest...)
	box = append(box, 0)
	box = binary.BigEndian.AppendUint64(box, 0) // Merkle offset
	data := at + len(box)
	box = append(box, store...)

	out := make([]byte, 0, len(b)+size)
	out = append(out, b[:at]...)
	out = append(out, box...)
	out = append(out, b[at:]...)
	if err := adjustOffsets(out, at, size); err != nil {
		return nil, nil, 0, err
	}
	nb := &Box{Type: "uuid", Path: "/uuid", Offset: at, Size: size, HeaderLen: hdr, UserType: out[at+hdr : at+hdr+16], HasVersion: true}
	return out, nb, data, nil
}

// Strip returns a copy of b without its C2PA manifest box, the meta/iloc
// offsets moved back. A file without one is returned unchanged (as a copy).
func Strip(b []byte) ([]byte, error) {
	t, err := Parse(b)
	if err != nil {
		return nil, err
	}
	bx, _, _, err := manifestBox(b, t)
	if err != nil {
		return nil, err
	}
	if bx == nil {
		return bytes.Clone(b), nil
	}
	out := make([]byte, 0, len(b)-bx.Size)
	out = append(out, b[:bx.Offset]...)
	out = append(out, b[bx.End():]...)
	if err := adjustOffsets(out, bx.Offset, -bx.Size); err != nil {
		return nil, err
	}
	return out, nil
}

// WriteStore overwrites bytes of a store Insert placed, without moving
// anything: data replaces [storeOff, storeOff+len(data)) of the store that
// starts at dataOff inside box.
func WriteStore(file []byte, box *Box, dataOff, storeOff int, data []byte) error {
	if box == nil || dataOff < box.Offset || storeOff < 0 || dataOff+storeOff+len(data) > box.End() || box.End() > len(file) {
		return fmt.Errorf("bmff: %w: store offset %d, %d bytes", ErrOutOfRange, storeOff, len(data))
	}
	copy(file[dataOff+storeOff:], data)
	return nil
}

// adjustOffsets moves the absolute file offsets in meta/iloc that point at
// or past `at` by delta, after delta bytes were inserted (or, negative,
// removed) at `at`. Items stored in idat (construction method 1), in other
// files (data_reference_index != 0) or as offsets into items (method 2)
// are relative and stay as they are.
func adjustOffsets(file []byte, at, delta int) error {
	t, err := Parse(file)
	if err != nil {
		return err
	}
	for _, iloc := range t.ByPath["/meta/iloc"] {
		if err := adjustIloc(file, iloc, at, delta); err != nil {
			return err
		}
	}
	return nil
}

// adjustIloc patches one ItemLocationBox (ISO/IEC 14496-12 §8.11.3).
func adjustIloc(file []byte, iloc *Box, at, delta int) error {
	r := &reader{b: file, p: iloc.Offset + iloc.HeaderLen, end: iloc.End()}
	version := r.u8()
	r.skip(3) // flags
	sizes := r.u8()
	sizes2 := r.u8()
	offSize, lenSize := int(sizes>>4), int(sizes&0x0f)
	baseSize, idxSize := int(sizes2>>4), int(sizes2&0x0f)
	if version > 2 {
		return fmt.Errorf("bmff: iloc version %d: %w", version, ErrUnsupported)
	}
	if version == 0 {
		idxSize = 0 // reserved in version 0
	}
	for _, s := range []int{offSize, lenSize, baseSize, idxSize} {
		if s != 0 && s != 4 && s != 8 {
			return fmt.Errorf("bmff: iloc field size %d: %w", s, ErrMalformed)
		}
	}
	var items uint64
	if version < 2 {
		items = uint64(r.u16())
	} else {
		items = uint64(r.u32())
	}
	shift := func(pos, size int) {
		if size == 0 || r.err != nil {
			return
		}
		v := readN(file, pos, size)
		if v == 0 || v < uint64(at) {
			return // no offset, or before the change
		}
		nv := int64(v) + int64(delta)
		if nv < 0 || (size == 4 && nv > math.MaxUint32) {
			r.err = fmt.Errorf("bmff: iloc offset %d cannot move by %d: %w", v, delta, ErrMalformed)
			return
		}
		writeN(file, pos, size, uint64(nv))
	}
	for i := uint64(0); i < items && r.err == nil; i++ {
		if version < 2 {
			r.skip(2) // item_ID
		} else {
			r.skip(4)
		}
		method := 0
		if version >= 1 {
			method = int(r.u16() & 0x0f)
		}
		dataRef := r.u16()
		basePos := r.p
		base := r.n(baseSize)
		fileOffsets := method == 0 && dataRef == 0
		if fileOffsets {
			shift(basePos, baseSize)
		}
		extents := int(r.u16())
		for e := 0; e < extents && r.err == nil; e++ {
			r.skip(idxSize)
			extPos := r.p
			r.skip(offSize)
			r.skip(lenSize)
			if fileOffsets && base == 0 {
				shift(extPos, offSize) // absolute when there is no base offset
			}
		}
	}
	if r.err != nil {
		return r.err
	}
	return nil
}

func readN(b []byte, p, size int) uint64 {
	if size == 4 {
		return uint64(binary.BigEndian.Uint32(b[p:]))
	}
	return binary.BigEndian.Uint64(b[p:])
}

func writeN(b []byte, p, size int, v uint64) {
	if size == 4 {
		binary.BigEndian.PutUint32(b[p:], uint32(v))
		return
	}
	binary.BigEndian.PutUint64(b[p:], v)
}

// reader reads big-endian fields inside a box, recording the first overrun.
type reader struct {
	b      []byte
	p, end int
	err    error
}

func (r *reader) need(n int) bool {
	if r.err == nil && r.p+n > r.end {
		r.err = fmt.Errorf("bmff: iloc box: %w", ErrTruncated)
	}
	return r.err == nil
}

func (r *reader) skip(n int) {
	if r.need(n) {
		r.p += n
	}
}

func (r *reader) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	r.p++
	return r.b[r.p-1]
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	r.p += 2
	return binary.BigEndian.Uint16(r.b[r.p-2:])
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	r.p += 4
	return binary.BigEndian.Uint32(r.b[r.p-4:])
}

func (r *reader) n(size int) uint64 {
	if size == 0 || !r.need(size) {
		return 0
	}
	v := readN(r.b, r.p, size)
	r.p += size
	return v
}
