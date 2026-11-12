package jpeg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// XMPNamespace starts the payload of an APP1 segment holding XMP (the
// namespace URI and a NUL byte).
const XMPNamespace = "http://ns.adobe.com/xap/1.0/\x00"

// maxXMP is the largest packet one APP1 segment can hold. Extended XMP
// (several segments) is not supported.
const maxXMP = 0xFFFF - 2 - len(XMPNamespace)

// ErrXMPTooLarge is returned by SetXMP for a packet that does not fit in one
// APP1 segment.
var ErrXMPTooLarge = errors.New("jpeg: XMP packet too large for one APP1 segment")

// XMP returns the XMP packet of the first APP1 XMP segment, and that
// segment. ok is false if there is none.
func XMP(b []byte) (packet []byte, seg Segment, ok bool, err error) {
	segs, err := Segments(b)
	if err != nil {
		return nil, Segment{}, false, err
	}
	for _, s := range segs {
		if s.Marker == APP1 && bytes.HasPrefix(s.Payload(b), []byte(XMPNamespace)) {
			return s.Payload(b)[len(XMPNamespace):], s, true, nil
		}
	}
	return nil, Segment{}, false, nil
}

// SetXMP returns a copy of b whose XMP packet is packet: the first APP1 XMP
// segment is replaced, or, if there is none, a new one is inserted after
// SOI and any APP0 / APP1 segments that directly follow it.
func SetXMP(b, packet []byte) ([]byte, error) {
	if len(packet) > maxXMP {
		return nil, fmt.Errorf("%w: %d bytes", ErrXMPTooLarge, len(packet))
	}
	segs, err := Segments(b)
	if err != nil {
		return nil, err
	}
	seg := make([]byte, 0, 4+len(XMPNamespace)+len(packet))
	seg = append(seg, 0xFF, APP1)
	seg = binary.BigEndian.AppendUint16(seg, uint16(2+len(XMPNamespace)+len(packet)))
	seg = append(seg, XMPNamespace...)
	seg = append(seg, packet...)

	from, to := -1, -1
	for _, s := range segs {
		if s.Marker == APP1 && bytes.HasPrefix(s.Payload(b), []byte(XMPNamespace)) {
			from, to = s.Offset, s.End()
			break
		}
	}
	if from < 0 {
		from = 2
		for _, s := range segs[1:] {
			if s.Marker != APP0 && s.Marker != APP1 {
				break
			}
			from = s.End()
		}
		to = from
	}
	out := make([]byte, 0, len(b)-(to-from)+len(seg))
	out = append(out, b[:from]...)
	out = append(out, seg...)
	return append(out, b[to:]...), nil
}
