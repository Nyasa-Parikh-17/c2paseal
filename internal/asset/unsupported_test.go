package asset

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func ftyp(brand string) []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint32(b, 24)
	copy(b[4:], "ftyp"+brand+"\x00\x00\x00\x00"+brand)
	return b
}

func TestDescribe(t *testing.T) {
	bmp := make([]byte, 30)
	copy(bmp, "BM")
	binary.LittleEndian.PutUint32(bmp[2:], 30)
	for _, tc := range []struct {
		name string
		b    []byte
		want string // substring; "" means Describe must return ""
	}{
		{"empty", nil, "an empty file"},
		{"mp4", ftyp("isom"), "an MP4 video"},
		{"mov", ftyp("qt  "), "QuickTime (MOV) video"},
		{"3gp", ftyp("3gp5"), "3GP video"},
		{"cr3", ftyp("crx "), "Canon CR3"},
		{"heic is supported", ftyp("heic"), ""},
		{"avif is supported", ftyp("avif"), ""},
		{"jpeg is supported", []byte{0xFF, 0xD8, 0xFF, 0xE0}, ""},
		{"gif", []byte("GIF89a\x01\x00"), "a GIF image"},
		{"pdf", []byte("%PDF-1.7\n"), "a PDF document"},
		{"tiff", []byte("II*\x00\x08\x00\x00\x00"), "a TIFF image"},
		{"bmp", bmp, "a BMP image"},
		{"wav", []byte("RIFF\x24\x00\x00\x00WAVEfmt "), "a WAV audio file"},
		{"avi", []byte("RIFF\x24\x00\x00\x00AVI LIST"), "an AVI video"},
		{"mp3", []byte("ID3\x04\x00"), "an MP3 audio file"},
		{"webm", []byte{0x1A, 0x45, 0xDF, 0xA3, 0x9F}, "Matroska or WebM"},
		{"svg", []byte("<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), "an SVG image"},
		{"zip", []byte("PK\x03\x04\x14\x00"), "a ZIP archive"},
		{"text", []byte("hello, world"), ""},
	} {
		got := Describe(tc.b)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: Describe = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestUnsupported(t *testing.T) {
	err := Unsupported(ftyp("isom"))
	if !errors.Is(err, ErrUnsupportedFormat) || !strings.Contains(err.Error(), "MP4 video") || !strings.Contains(err.Error(), Supported) {
		t.Errorf("MP4: %v", err)
	}
	err = Unsupported([]byte("hello"))
	if !errors.Is(err, ErrUnsupportedFormat) || !strings.HasSuffix(err.Error(), "C2paSeal supports "+Supported+" only") {
		t.Errorf("unknown: %v", err)
	}
	if _, _, err := Extract(ftyp("qt  ")); !errors.Is(err, ErrUnsupportedFormat) || !strings.Contains(err.Error(), "QuickTime") {
		t.Errorf("Extract(MOV): %v", err)
	}
}
