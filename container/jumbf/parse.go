package jumbf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// maxDepth bounds superbox nesting so hostile input cannot exhaust the stack.
// C2PA manifest stores nest about five levels deep.
const maxDepth = 32

// Parse parses b as exactly one JUMBF box, normally a C2PA manifest store
// superbox. The returned tree shares memory with b.
func Parse(b []byte) (*Box, error) {
	boxes, err := ParseAll(b)
	if err != nil {
		return nil, err
	}
	if len(boxes) != 1 {
		return nil, fmt.Errorf("jumbf: %w: found %d boxes", ErrTopLevel, len(boxes))
	}
	return boxes[0], nil
}

// ParseAll parses b as a sequence of boxes that fills it exactly.
func ParseAll(b []byte) ([]*Box, error) {
	return parseBoxes(b, 0, 0)
}

func parseBoxes(b []byte, base, depth int) ([]*Box, error) {
	var out []*Box
	for off := 0; off < len(b); {
		box, n, err := parseBox(b[off:], base+off, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, box)
		off += n
	}
	return out, nil
}

// parseBox parses the box at the start of b, which sits at offset abs in the
// original input, and returns it with its total length.
func parseBox(b []byte, abs, depth int) (*Box, int, error) {
	fail := func(err error) (*Box, int, error) {
		return nil, 0, fmt.Errorf("jumbf: parse box at offset %d: %w", abs, err)
	}
	if len(b) < 8 {
		return fail(ErrTruncated)
	}
	box := &Box{Type: string(b[4:8]), Offset: abs}
	hdr := 8
	var size uint64
	switch lbox := binary.BigEndian.Uint32(b); lbox {
	case 0:
		box.Form = ToEnd
		size = uint64(len(b))
	case 1:
		box.Form = Extended
		hdr = 16
		if len(b) < 16 {
			return fail(ErrTruncated)
		}
		if size = binary.BigEndian.Uint64(b[8:]); size < 16 {
			return fail(fmt.Errorf("%w: XLBox %d", ErrBadLength, size))
		}
	default:
		if lbox < 8 {
			return fail(fmt.Errorf("%w: LBox %d", ErrBadLength, lbox))
		}
		size = uint64(lbox)
	}
	if size > uint64(len(b)) {
		return fail(fmt.Errorf("%w: length %d, %d bytes available", ErrTruncated, size, len(b)))
	}

	box.Raw = b[:size:size]
	payload := box.Raw[hdr:]
	switch box.Type {
	case TypeSuperbox:
		if depth >= maxDepth {
			return fail(ErrTooDeep)
		}
		children, err := parseBoxes(payload, abs+hdr, depth+1)
		if err != nil {
			return nil, 0, err
		}
		if len(children) == 0 || children[0].Type != TypeDescription {
			return fail(ErrNoDescription)
		}
		box.Children = children
	case TypeDescription:
		d, err := parseDescription(payload, abs+hdr, depth)
		if err != nil {
			return fail(err)
		}
		box.Description = d
	default:
		box.Payload = payload
	}
	return box, int(size), nil
}

func parseDescription(p []byte, abs, depth int) (*Description, error) {
	if len(p) < 17 {
		return nil, fmt.Errorf("%w: description needs 17 bytes, has %d", ErrTruncated, len(p))
	}
	d := &Description{Toggles: p[16]}
	copy(d.ContentType[:], p)
	rest := p[17:]

	if d.Toggles&ToggleLabel != 0 {
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			return nil, fmt.Errorf("%w: label has no NUL terminator", ErrTruncated)
		}
		d.Label = string(rest[:i])
		rest = rest[i+1:]
	}
	if d.Toggles&ToggleID != 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: description ID", ErrTruncated)
		}
		d.ID = binary.BigEndian.Uint32(rest)
		rest = rest[4:]
	}
	if d.Toggles&ToggleHash != 0 {
		if len(rest) < 32 {
			return nil, fmt.Errorf("%w: description hash", ErrTruncated)
		}
		d.Hash = rest[:32:32]
		rest = rest[32:]
	}
	if d.Toggles&TogglePrivate != 0 {
		if depth >= maxDepth {
			return nil, ErrTooDeep
		}
		priv, n, err := parseBox(rest, abs+len(p)-len(rest), depth+1)
		if err != nil {
			return nil, err
		}
		d.Private = priv
		rest = rest[n:]
	}
	if len(rest) > 0 {
		d.Extra = rest
	}
	return d, nil
}
