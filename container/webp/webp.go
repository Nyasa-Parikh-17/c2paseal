// Package webp reads and writes the C2PA manifest store in WebP files.
//
// A WebP file is a RIFF container: "RIFF", a little-endian 32-bit size,
// "WEBP", then chunks of a FourCC, a little-endian 32-bit data length, the
// data and a pad byte when the length is odd. The manifest store is the
// data of a top-level "C2PA" chunk. Like c2pa-rs (riff_io.rs), Insert puts
// it last in the RIFF and does not change VP8X; the c2pa.hash.data
// exclusion is the chunk's 8-byte header plus its data, without the pad
// byte (ExclusionLength).
//
// Reading and writing keep every other byte as it was: Strip(Insert(b, s))
// is b, byte for byte.
package webp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
)

// FourCCs this package knows.
const (
	FourCCC2PA = "C2PA"
	FourCCVP8X = "VP8X"
	FourCCVP8  = "VP8 "
	FourCCVP8L = "VP8L"
	FourCCXMP  = "XMP "
)

const (
	headerLen   = 12 // "RIFF", size, "WEBP"
	chunkHeader = 8  // FourCC, length
)

var (
	ErrNotWebP        = errors.New("not a WebP file")
	ErrTruncated      = errors.New("truncated chunk")
	ErrNoManifest     = errors.New("no C2PA chunk")
	ErrMultipleStores = errors.New("more than one C2PA chunk")
	ErrHasManifest    = errors.New("file already has a C2PA chunk")
	ErrTooLarge       = errors.New("manifest store too large for a RIFF chunk")
	ErrOutOfRange     = errors.New("write outside the inserted manifest store")
)

// IsWebP reports whether b starts like a WebP file.
func IsWebP(b []byte) bool {
	return len(b) >= headerLen && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WEBP"
}

// Chunk is a top-level chunk of the RIFF.
type Chunk struct {
	FourCC string
	Offset int // of the chunk header in the file
	Length int // of the data, without the header and pad byte
}

// Size is the chunk's size in the file: header, data and pad byte.
func (c Chunk) Size() int { return chunkHeader + c.Length + c.Length&1 }

// End is the offset just after the chunk (after its pad byte).
func (c Chunk) End() int { return c.Offset + c.Size() }

// Data returns the chunk's data in b.
func (c Chunk) Data(b []byte) []byte { return b[c.Offset+chunkHeader : c.Offset+chunkHeader+c.Length] }

// ExclusionLength is the length the c2pa.hash.data exclusion for a C2PA
// chunk covers from its Offset: the header and the data, as c2pa-rs
// excludes it (the pad byte, if any, is hashed).
func (c Chunk) ExclusionLength() int { return chunkHeader + c.Length }

// riffEnd returns where the RIFF's data ends, from its size field. Bytes
// after it (rare) are not part of the RIFF and are left alone.
func riffEnd(b []byte) (int, error) {
	if !IsWebP(b) {
		return 0, fmt.Errorf("webp: %w", ErrNotWebP)
	}
	size := uint64(binary.LittleEndian.Uint32(b[4:8]))
	end := 8 + size
	if size < 4 || end > uint64(len(b)) {
		return 0, fmt.Errorf("webp: RIFF size %d does not fit the %d-byte file: %w", size, len(b), ErrTruncated)
	}
	return int(end), nil
}

// Chunks returns the RIFF's top-level chunks in order. Every chunk,
// including its pad byte, must fit inside the RIFF (a missing pad byte at
// the very end is accepted, as libwebp does).
func Chunks(b []byte) ([]Chunk, error) {
	end, err := riffEnd(b)
	if err != nil {
		return nil, err
	}
	var out []Chunk
	for off := headerLen; off < end; {
		if end-off < chunkHeader {
			return nil, fmt.Errorf("webp: chunk header at offset %d: %w", off, ErrTruncated)
		}
		n := uint64(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		dataEnd := uint64(off) + chunkHeader + n
		if dataEnd > uint64(end) {
			return nil, fmt.Errorf("webp: chunk %q at offset %d: %d bytes past the RIFF end: %w", b[off:off+4], off, dataEnd-uint64(end), ErrTruncated)
		}
		c := Chunk{FourCC: string(b[off : off+4]), Offset: off, Length: int(n)}
		out = append(out, c)
		off = min(c.End(), end)
	}
	return out, nil
}

// Store is a C2PA manifest store read from a WebP file.
type Store struct {
	Root  *jumbf.Box // parsed manifest store; shares memory with the input
	JUMBF []byte     // the C2PA chunk's data
	Chunk Chunk      // the C2PA chunk
}

func findStore(chunks []Chunk) (c Chunk, ok bool, err error) {
	for _, ch := range chunks {
		if ch.FourCC != FourCCC2PA {
			continue
		}
		if ok {
			return Chunk{}, false, fmt.Errorf("webp: %w", ErrMultipleStores)
		}
		c, ok = ch, true
	}
	return c, ok, nil
}

// Extract reads and parses the manifest store from the C2PA chunk. It
// returns ErrNoManifest if there is none.
func Extract(b []byte) (*Store, error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, err
	}
	c, ok, err := findStore(chunks)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("webp: %w", ErrNoManifest)
	}
	data := c.Data(b)
	root, err := jumbf.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("webp: manifest store: %w", err)
	}
	return &Store{Root: root, JUMBF: data, Chunk: c}, nil
}

// Strip returns a copy of b without its C2PA chunk, with the RIFF size
// corrected. A file without one is returned unchanged (as a copy).
func Strip(b []byte) ([]byte, error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, err
	}
	c, ok, err := findStore(chunks)
	if err != nil {
		return nil, err
	}
	if !ok {
		return bytes.Clone(b), nil
	}
	end, _ := riffEnd(b)
	cut := min(c.End(), end) - c.Offset
	out := make([]byte, 0, len(b)-cut)
	out = append(out, b[:c.Offset]...)
	out = append(out, b[c.Offset+cut:]...)
	binary.LittleEndian.PutUint32(out[4:8], binary.LittleEndian.Uint32(b[4:8])-uint32(cut))
	return out, nil
}

// InsertedSize returns how many bytes Insert adds for a store of storeLen
// bytes: header, data and pad byte.
func InsertedSize(storeLen int) int { return chunkHeader + storeLen + storeLen&1 }

// Insert returns a copy of b with store in a C2PA chunk at the end of the
// RIFF (where c2pa-rs puts it), the RIFF size updated, and the new chunk's
// position in the result. A file that ends without the pad byte of its
// last chunk gets it first, so the new chunk starts on an even offset.
func Insert(b, store []byte) ([]byte, Chunk, error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, Chunk{}, err
	}
	if _, ok, err := findStore(chunks); err != nil {
		return nil, Chunk{}, err
	} else if ok {
		return nil, Chunk{}, fmt.Errorf("webp: %w", ErrHasManifest)
	}
	end, _ := riffEnd(b)
	pad := 0
	if len(chunks) > 0 && chunks[len(chunks)-1].End() > end {
		pad = 1
	}
	add := pad + InsertedSize(len(store))
	newSize := uint64(binary.LittleEndian.Uint32(b[4:8])) + uint64(add)
	if newSize > math.MaxUint32 || uint64(len(store)) > math.MaxUint32 {
		return nil, Chunk{}, fmt.Errorf("webp: %w: %d bytes", ErrTooLarge, len(store))
	}
	out := make([]byte, 0, len(b)+add)
	out = append(out, b[:end]...)
	if pad == 1 {
		out = append(out, 0)
	}
	at := len(out)
	out = append(out, FourCCC2PA...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(store)))
	out = append(out, store...)
	if len(store)&1 == 1 {
		out = append(out, 0)
	}
	out = append(out, b[end:]...)
	binary.LittleEndian.PutUint32(out[4:8], uint32(newSize))
	return out, Chunk{FourCC: FourCCC2PA, Offset: at, Length: len(store)}, nil
}

// WriteStore overwrites bytes of a manifest store that Insert has already
// placed in file, without moving anything: data replaces the store bytes
// at [storeOff, storeOff+len(data)) of chunk c's data.
func WriteStore(file []byte, c Chunk, storeOff int, data []byte) error {
	if c.Offset < 0 || storeOff < 0 || storeOff+len(data) > c.Length || c.Offset+chunkHeader+c.Length > len(file) {
		return fmt.Errorf("webp: %w: store offset %d, %d bytes", ErrOutOfRange, storeOff, len(data))
	}
	copy(file[c.Offset+chunkHeader+storeOff:], data)
	return nil
}
