package png

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

// TypeITXt is the international text chunk that carries XMP.
const TypeITXt = "iTXt"

// XMPKeyword is the iTXt keyword of an XMP packet.
const XMPKeyword = "XML:com.adobe.xmp"

// maxXMP bounds a decompressed XMP packet.
const maxXMP = 16 << 20

// ErrBadITXt is returned for an XMP iTXt chunk that cannot be read.
var ErrBadITXt = errors.New("malformed XMP iTXt chunk")

// XMP returns the packet of the first XMP iTXt chunk, decompressing it if
// needed. ok is false if there is none.
func XMP(b []byte) (packet []byte, ok bool, err error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, false, err
	}
	for _, c := range chunks {
		if c.Type != TypeITXt {
			continue
		}
		data := c.Data(b)
		if !bytes.HasPrefix(data, []byte(XMPKeyword+"\x00")) {
			continue
		}
		p, err := itxtText(data[len(XMPKeyword)+1:])
		if err != nil {
			return nil, false, fmt.Errorf("png: %w at offset %d: %v", ErrBadITXt, c.Offset, err)
		}
		return p, true, nil
	}
	return nil, false, nil
}

// itxtText reads the part of an iTXt chunk after the keyword's NUL:
// compression flag, method, language tag NUL, translated keyword NUL, text.
func itxtText(p []byte) ([]byte, error) {
	if len(p) < 2 {
		return nil, errors.New("too short")
	}
	flag, method := p[0], p[1]
	p = p[2:]
	for range 2 { // language tag, translated keyword
		i := bytes.IndexByte(p, 0)
		if i < 0 {
			return nil, errors.New("missing NUL separator")
		}
		p = p[i+1:]
	}
	switch {
	case flag == 0:
		return p, nil
	case flag == 1 && method == 0:
		r, err := zlib.NewReader(bytes.NewReader(p))
		if err != nil {
			return nil, err
		}
		out, err := io.ReadAll(io.LimitReader(r, maxXMP+1))
		if err != nil {
			return nil, err
		}
		if len(out) > maxXMP {
			return nil, errors.New("decompressed packet too large")
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown compression %d/%d", flag, method)
}

// SetXMP returns a copy of b whose XMP packet is packet, stored
// uncompressed: the first XMP iTXt chunk is replaced, or, if there is none,
// a new one is inserted straight after IHDR.
func SetXMP(b, packet []byte) ([]byte, error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, len(XMPKeyword)+5+len(packet))
	data = append(data, XMPKeyword...)
	data = append(data, 0, 0, 0, 0, 0) // keyword NUL, uncompressed, method 0, empty language, empty translation
	data = append(data, packet...)
	if uint64(len(data)) > math.MaxInt32 {
		return nil, fmt.Errorf("png: %w: XMP packet of %d bytes", ErrTooLarge, len(packet))
	}
	chunk := make([]byte, 0, chunkOverhead+len(data))
	chunk = binary.BigEndian.AppendUint32(chunk, uint32(len(data)))
	chunk = append(chunk, TypeITXt...)
	chunk = append(chunk, data...)
	chunk = binary.BigEndian.AppendUint32(chunk, crc32.ChecksumIEEE(chunk[4:]))

	from, to := -1, -1
	for _, c := range chunks {
		if c.Type == TypeITXt && bytes.HasPrefix(c.Data(b), []byte(XMPKeyword+"\x00")) {
			from, to = c.Offset, c.End()
			break
		}
	}
	if from < 0 {
		for _, c := range chunks {
			if c.Type == TypeIHDR {
				from, to = c.End(), c.End()
				break
			}
		}
	}
	if from < 0 {
		return nil, fmt.Errorf("png: %w", ErrNoIHDR)
	}
	out := make([]byte, 0, len(b)-(to-from)+len(chunk))
	out = append(out, b[:from]...)
	out = append(out, chunk...)
	return append(out, b[to:]...), nil
}
