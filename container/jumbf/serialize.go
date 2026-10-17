package jumbf

import (
	"encoding/binary"
	"math"
)

// Serialize encodes b and its descendants. For a tree returned by Parse the
// result equals the parsed bytes.
func Serialize(b *Box) []byte {
	return Append(make([]byte, 0, b.Size()), b)
}

// Append appends the encoding of b to dst.
func Append(dst []byte, b *Box) []byte {
	size := b.Size()
	var typ [4]byte
	copy(typ[:], b.Type)
	switch {
	case b.Form == ToEnd:
		dst = binary.BigEndian.AppendUint32(dst, 0)
		dst = append(dst, typ[:]...)
	case b.extended():
		dst = binary.BigEndian.AppendUint32(dst, 1)
		dst = append(dst, typ[:]...)
		dst = binary.BigEndian.AppendUint64(dst, uint64(size))
	default:
		dst = binary.BigEndian.AppendUint32(dst, uint32(size))
		dst = append(dst, typ[:]...)
	}

	switch {
	case b.Type == TypeSuperbox:
		for _, c := range b.Children {
			dst = Append(dst, c)
		}
	case b.Type == TypeDescription && b.Description != nil:
		dst = appendDescription(dst, b.Description)
	default:
		dst = append(dst, b.Payload...)
	}
	return dst
}

// Bytes returns b's encoding: its original bytes if it was parsed (Raw),
// otherwise Serialize(b). Raw does not track later edits to a parsed box.
func (b *Box) Bytes() []byte {
	if b.Raw != nil {
		return b.Raw
	}
	return Serialize(b)
}

// HeaderLen returns the length of b's header: 16 with an XLBox, else 8.
func (b *Box) HeaderLen() int {
	if b.extended() {
		return 16
	}
	return 8
}

// Size returns the encoded length of b, header included.
func (b *Box) Size() int {
	p := b.payloadSize()
	if b.extended() {
		return p + 16
	}
	return p + 8
}

// extended reports whether the header needs an XLBox: either it had one, or
// a Compact box is too large for a 4-byte length.
func (b *Box) extended() bool {
	return b.Form == Extended || (b.Form == Compact && b.payloadSize()+8 > math.MaxUint32)
}

func (b *Box) payloadSize() int {
	switch {
	case b.Type == TypeSuperbox:
		n := 0
		for _, c := range b.Children {
			n += c.Size()
		}
		return n
	case b.Type == TypeDescription && b.Description != nil:
		return b.Description.size()
	default:
		return len(b.Payload)
	}
}

func (d *Description) size() int {
	n := 17 + len(d.Extra)
	if d.Toggles&ToggleLabel != 0 {
		n += len(d.Label) + 1
	}
	if d.Toggles&ToggleID != 0 {
		n += 4
	}
	if d.Toggles&ToggleHash != 0 {
		n += 32
	}
	if d.Toggles&TogglePrivate != 0 && d.Private != nil {
		n += d.Private.Size()
	}
	return n
}

func appendDescription(dst []byte, d *Description) []byte {
	dst = append(dst, d.ContentType[:]...)
	dst = append(dst, d.Toggles)
	if d.Toggles&ToggleLabel != 0 {
		dst = append(dst, d.Label...)
		dst = append(dst, 0)
	}
	if d.Toggles&ToggleID != 0 {
		dst = binary.BigEndian.AppendUint32(dst, d.ID)
	}
	if d.Toggles&ToggleHash != 0 {
		var h [32]byte
		copy(h[:], d.Hash)
		dst = append(dst, h[:]...)
	}
	if d.Toggles&TogglePrivate != 0 && d.Private != nil {
		dst = Append(dst, d.Private)
	}
	return append(dst, d.Extra...)
}
