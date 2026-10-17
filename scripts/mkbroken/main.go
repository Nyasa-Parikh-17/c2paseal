// Command mkbroken derives the broken fixtures in testdata/broken from the
// signed ones. Each variant makes exactly one targeted change.
//
// It locates boxes by searching for their JUMBF labels in the raw file, which
// is enough for single-APP11-segment fixtures. It is deliberately not the
// library's parser, so a parser bug cannot hide a broken fixture.
//
// Usage: go run ./scripts/mkbroken <signed-dir> <broken-dir>
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
)

type variant struct {
	out, src string
	mutate   func([]byte) ([]byte, error)
}

var variants = []variant{
	{"data-flip.jpg", "small.jpg", flipJPEGScan},
	{"sig-flip.jpg", "small.jpg", flipSignature},
	{"assertion-flip.jpg", "small.jpg", flipAssertion},
	{"truncated-app11.jpg", "small.jpg", truncateAPP11},
	{"bad-jumbf-length.jpg", "small.jpg", badJUMBFLength},
	{"data-flip.png", "small.png", flipPNGData},
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: mkbroken <signed-dir> <broken-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "mkbroken:", err)
		os.Exit(1)
	}
}

func run(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, v := range variants {
		b, err := os.ReadFile(filepath.Join(src, v.src))
		if err != nil {
			return err
		}
		out, err := v.mutate(bytes.Clone(b))
		if err != nil {
			return fmt.Errorf("%s: %w", v.out, err)
		}
		if err := os.WriteFile(filepath.Join(dst, v.out), out, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// jpegSegments returns the offset of each marker segment before SOS and the
// offset where SOS starts.
func jpegSegments(b []byte) (segs []int, sos int, err error) {
	i := 2
	for i+4 <= len(b) && b[i] == 0xFF {
		if b[i+1] == 0xDA {
			return segs, i, nil
		}
		segs = append(segs, i)
		i += 2 + int(binary.BigEndian.Uint16(b[i+2:]))
	}
	return nil, 0, errors.New("no SOS marker")
}

// flipJPEGScan flips one bit in the middle of the entropy-coded data,
// avoiding bytes that would create or destroy a 0xFF marker prefix.
func flipJPEGScan(b []byte) ([]byte, error) {
	_, sos, err := jpegSegments(b)
	if err != nil {
		return nil, err
	}
	for i := sos + (len(b)-sos)/2; i < len(b)-2; i++ {
		if b[i] != 0xFF && b[i]^0x01 != 0xFF && b[i-1] != 0xFF {
			b[i] ^= 0x01
			return b, nil
		}
	}
	return nil, errors.New("no flippable scan byte")
}

// contentBoxAfterLabel finds the JUMBF description box carrying label and
// returns the offset and length of the content box that follows it.
func contentBoxAfterLabel(b []byte, label string) (off, n int, err error) {
	i := bytes.Index(b, append([]byte(label), 0))
	if i < 0 {
		return 0, 0, fmt.Errorf("label %q not found", label)
	}
	jumd := i - 8 - 16 - 1 // box header, content-type UUID, toggles
	if string(b[jumd+4:jumd+8]) != "jumd" {
		return 0, 0, fmt.Errorf("label %q: no jumd box", label)
	}
	off = jumd + int(binary.BigEndian.Uint32(b[jumd:]))
	n = int(binary.BigEndian.Uint32(b[off:]))
	return off, n, nil
}

// flipSignature flips the last byte of the COSE_Sign1 signature, which is
// the final element of the c2pa.signature content box.
func flipSignature(b []byte) ([]byte, error) {
	off, n, err := contentBoxAfterLabel(b, "c2pa.signature")
	if err != nil {
		return nil, err
	}
	b[off+n-1] ^= 0x01
	return b, nil
}

// flipAssertion changes one character inside the actions assertion, so its
// hashed URI in the claim no longer matches.
func flipAssertion(b []byte) ([]byte, error) {
	off, n, err := contentBoxAfterLabel(b, "c2pa.actions.v2")
	if err != nil {
		return nil, err
	}
	i := bytes.Index(b[off:off+n], []byte("c2pa.created"))
	if i < 0 {
		return nil, errors.New("c2pa.created not found in actions")
	}
	b[off+i+len("c2pa.create")] = 'D'
	return b, nil
}

// truncateAPP11 cuts the file in the middle of the first APP11 segment.
func truncateAPP11(b []byte) ([]byte, error) {
	segs, _, err := jpegSegments(b)
	if err != nil {
		return nil, err
	}
	for _, s := range segs {
		if b[s+1] == 0xEB {
			return b[:s+int(binary.BigEndian.Uint16(b[s+2:]))/2], nil
		}
	}
	return nil, errors.New("no APP11 segment")
}

// badJUMBFLength makes the c2pa.assertions superbox claim a length far past
// the end of the manifest store.
func badJUMBFLength(b []byte) ([]byte, error) {
	i := bytes.Index(b, []byte("c2pa.assertions\x00"))
	if i < 0 {
		return nil, errors.New("c2pa.assertions not found")
	}
	jumb := i - 8 - 16 - 1 - 8
	if string(b[jumb+4:jumb+8]) != "jumb" {
		return nil, errors.New("c2pa.assertions: no jumb box")
	}
	binary.BigEndian.PutUint32(b[jumb:], 0x7FFFFFF0)
	return b, nil
}

// flipPNGData flips one bit in the first IDAT chunk and fixes its CRC, so
// only the hard binding is broken.
func flipPNGData(b []byte) ([]byte, error) {
	for i := 8; i+12 <= len(b); {
		n := int(binary.BigEndian.Uint32(b[i:]))
		if string(b[i+4:i+8]) == "IDAT" {
			b[i+8+n/2] ^= 0x01
			binary.BigEndian.PutUint32(b[i+8+n:], crc32.ChecksumIEEE(b[i+4:i+8+n]))
			return b, nil
		}
		i += 12 + n
	}
	return nil, errors.New("no IDAT chunk")
}
