package webp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// VP8X flag bits (WebP container specification, "Extended file format").
const (
	flagXMP   = 0x04
	flagAlpha = 0x10
)

var ErrNoImage = errors.New("no VP8 or VP8L image chunk")

// XMP returns the data of the "XMP " chunk, if there is one.
func XMP(b []byte) (packet []byte, ok bool, err error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, false, err
	}
	for _, c := range chunks {
		if c.FourCC == FourCCXMP {
			return c.Data(b), true, nil
		}
	}
	return nil, false, nil
}

// SetXMP returns a copy of b whose "XMP " chunk holds packet: the existing
// chunk is replaced where it is, or a new one goes before the C2PA chunk
// (or last). The VP8X chunk gets its XMP flag; a simple-format file, which
// has none, gets one first, built from the VP8 or VP8L image size, as
// c2pa-rs does. The RIFF size is updated.
func SetXMP(b, packet []byte) ([]byte, error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, err
	}
	if uint64(len(packet)) > math.MaxUint32 {
		return nil, fmt.Errorf("webp: XMP: %w", ErrTooLarge)
	}
	end, _ := riffEnd(b)
	xmp := appendChunk(nil, FourCCXMP, packet)

	var out []byte
	out = append(out, b[:headerLen]...)
	var vp8x Chunk
	hasVP8X := false
	for _, c := range chunks {
		if c.FourCC == FourCCVP8X {
			vp8x, hasVP8X = c, true
			break
		}
	}
	if !hasVP8X {
		w, h, alpha, err := imageSize(b, chunks)
		if err != nil {
			return nil, err
		}
		var d [10]byte
		if alpha {
			d[0] = flagAlpha
		}
		putUint24(d[4:7], uint32(w-1))
		putUint24(d[7:10], uint32(h-1))
		out = appendChunk(out, FourCCVP8X, d[:])
	}

	placed := false
	for _, c := range chunks {
		switch {
		case c.FourCC == FourCCXMP:
			if !placed {
				out = append(out, xmp...)
				placed = true
			}
			continue // a duplicate XMP chunk is dropped
		case c.FourCC == FourCCC2PA && !placed:
			out = append(out, xmp...)
			placed = true
		}
		start := len(out)
		out = append(out, b[c.Offset:min(c.End(), end)]...)
		if c.End() > end { // the last chunk had no pad byte
			out = append(out, 0)
		}
		if hasVP8X && c.Offset == vp8x.Offset && c.Length >= 1 {
			out[start+chunkHeader] |= flagXMP
		}
	}
	if !placed {
		out = append(out, xmp...)
	}
	if !hasVP8X {
		out[headerLen+chunkHeader] |= flagXMP
	}
	size := uint64(len(out) - 8)
	if size > math.MaxUint32 {
		return nil, fmt.Errorf("webp: XMP: %w", ErrTooLarge)
	}
	binary.LittleEndian.PutUint32(out[4:8], uint32(size))
	return append(out, b[end:]...), nil
}

func appendChunk(out []byte, fourCC string, data []byte) []byte {
	out = append(out, fourCC...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(data)))
	out = append(out, data...)
	if len(data)&1 == 1 {
		out = append(out, 0)
	}
	return out
}

func putUint24(b []byte, v uint32) { b[0], b[1], b[2] = byte(v), byte(v>>8), byte(v>>16) }

// imageSize reads the canvas size from the VP8L or VP8 chunk, and whether a
// VP8L image uses alpha.
func imageSize(b []byte, chunks []Chunk) (w, h int, alpha bool, err error) {
	for _, c := range chunks {
		d := c.Data(b)
		switch c.FourCC {
		case FourCCVP8L:
			// 0x2f, then 14 bits width-1, 14 bits height-1, 1 bit alpha.
			if len(d) < 5 || d[0] != 0x2f {
				return 0, 0, false, errors.New("webp: VP8L chunk without its signature")
			}
			v := binary.LittleEndian.Uint32(d[1:5])
			return int(v&0x3fff) + 1, int(v>>14&0x3fff) + 1, v>>28&1 == 1, nil
		case FourCCVP8:
			// 3-byte frame tag, start code 9d 01 2a, 14-bit width and height.
			if len(d) < 10 || d[3] != 0x9d || d[4] != 0x01 || d[5] != 0x2a {
				return 0, 0, false, errors.New("webp: VP8 chunk without its start code")
			}
			return int(binary.LittleEndian.Uint16(d[6:8]) & 0x3fff), int(binary.LittleEndian.Uint16(d[8:10]) & 0x3fff), false, nil
		}
	}
	return 0, 0, false, fmt.Errorf("webp: %w", ErrNoImage)
}
