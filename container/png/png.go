package png

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
)

// Signature is the 8-byte PNG file signature.
const Signature = "\x89PNG\r\n\x1a\n"

// Chunk types used by this package.
const (
	TypeIHDR = "IHDR"
	TypeIEND = "IEND"
	TypeC2PA = "caBX"
)

// chunkOverhead is length + type + CRC.
const chunkOverhead = 12

// Errors returned by this package. Returned errors wrap one of these.
var (
	ErrNotPNG         = errors.New("not a PNG (bad signature)")
	ErrTruncated      = errors.New("truncated")
	ErrNoIHDR         = errors.New("no IHDR chunk")
	ErrNoManifest     = errors.New("no C2PA manifest store")
	ErrMultipleStores = errors.New("more than one caBX chunk")
	ErrHasManifest    = errors.New("PNG already has a C2PA manifest store")
	ErrTooLarge       = errors.New("manifest store too large for a PNG chunk")
)

// Chunk is one PNG chunk.
type Chunk struct {
	Type     string
	Offset   int  // offset of the chunk's length field
	Length   int  // data length (excludes length, type and CRC)
	CRCValid bool // stored CRC-32 matches type + data
}

// Size returns the chunk's total size: length, type, data and CRC.
func (c Chunk) Size() int { return chunkOverhead + c.Length }

// End returns the offset just past the chunk's CRC.
func (c Chunk) End() int { return c.Offset + c.Size() }

// Data returns the chunk's data bytes.
func (c Chunk) Data(b []byte) []byte { return b[c.Offset+8 : c.Offset+8+c.Length] }

// Chunks walks the chunks after the signature up to and including IEND.
// Bytes after IEND are ignored. CRC mismatches are recorded in
// Chunk.CRCValid, not reported as errors: c2pa-rs does not check them either.
func Chunks(b []byte) ([]Chunk, error) {
	if !bytes.HasPrefix(b, []byte(Signature)) {
		return nil, fmt.Errorf("png: %w", ErrNotPNG)
	}
	var chunks []Chunk
	for off := len(Signature); ; {
		if off+chunkOverhead > len(b) {
			return nil, fmt.Errorf("png: %w: chunk header at offset %d (no IEND)", ErrTruncated, off)
		}
		n := binary.BigEndian.Uint32(b[off:])
		if uint64(n) > uint64(len(b)-off-chunkOverhead) {
			return nil, fmt.Errorf("png: %w: chunk at offset %d declares %d bytes", ErrTruncated, off, n)
		}
		c := Chunk{Type: string(b[off+4 : off+8]), Offset: off, Length: int(n)}
		crc := binary.BigEndian.Uint32(b[c.End()-4:])
		c.CRCValid = crc == crc32.ChecksumIEEE(b[off+4:c.End()-4])
		chunks = append(chunks, c)
		if c.Type == TypeIEND {
			return chunks, nil
		}
		off = c.End()
	}
}

// Store is a C2PA manifest store read from a PNG.
type Store struct {
	Root  *jumbf.Box // parsed manifest store; shares memory with the input
	JUMBF []byte     // the caBX chunk data
	Chunk Chunk      // the caBX chunk
}

// findStore returns the caBX chunk, or ok = false if there is none.
func findStore(chunks []Chunk) (c Chunk, ok bool, err error) {
	for _, ch := range chunks {
		if ch.Type != TypeC2PA {
			continue
		}
		if ok {
			return Chunk{}, false, fmt.Errorf("png: %w", ErrMultipleStores)
		}
		c, ok = ch, true
	}
	return c, ok, nil
}

// Extract reads and parses the C2PA manifest store from the caBX chunk. It
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
		return nil, fmt.Errorf("png: %w", ErrNoManifest)
	}
	data := c.Data(b)
	root, err := jumbf.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("png: manifest store: %w", err)
	}
	return &Store{Root: root, JUMBF: data, Chunk: c}, nil
}

// Strip returns a copy of b without its caBX chunk. A PNG without one is
// returned unchanged (as a copy).
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
	out := make([]byte, 0, len(b)-c.Size())
	out = append(out, b[:c.Offset]...)
	return append(out, b[c.End():]...), nil
}

// InsertedSize returns how many bytes Insert adds for a store of storeLen bytes.
func InsertedSize(storeLen int) int { return storeLen + chunkOverhead }

// Insert returns a copy of b with store in a caBX chunk straight after IHDR
// (where c2pa-rs puts it, and so before the first IDAT), and the new chunk's
// position in the result.
func Insert(b, store []byte) ([]byte, Chunk, error) {
	chunks, err := Chunks(b)
	if err != nil {
		return nil, Chunk{}, err
	}
	if _, ok, err := findStore(chunks); err != nil {
		return nil, Chunk{}, err
	} else if ok {
		return nil, Chunk{}, fmt.Errorf("png: %w", ErrHasManifest)
	}
	if uint64(len(store)) > math.MaxInt32 {
		return nil, Chunk{}, fmt.Errorf("png: %w: %d bytes", ErrTooLarge, len(store))
	}
	at := -1
	for _, c := range chunks {
		if c.Type == TypeIHDR {
			at = c.End()
			break
		}
	}
	if at < 0 {
		return nil, Chunk{}, fmt.Errorf("png: %w", ErrNoIHDR)
	}

	out := make([]byte, 0, len(b)+InsertedSize(len(store)))
	out = append(out, b[:at]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(store)))
	out = append(out, TypeC2PA...)
	out = append(out, store...)
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out[at+4:]))
	out = append(out, b[at:]...)
	return out, Chunk{Type: TypeC2PA, Offset: at, Length: len(store), CRCValid: true}, nil
}
