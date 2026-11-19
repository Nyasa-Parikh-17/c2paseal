package asset

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Supported names the formats C2paSeal reads, verifies and signs, for
// messages.
const Supported = "JPEG, PNG, WebP, HEIC and AVIF images"

// Unsupported returns ErrUnsupportedFormat for b, saying what the file
// looks like when it is a common format C2paSeal does not handle (a video,
// a PDF, a GIF, ...), and which formats are supported.
func Unsupported(b []byte) error {
	if kind := Describe(b); kind != "" {
		return fmt.Errorf("%w: the file looks like %s; C2paSeal supports %s only", ErrUnsupportedFormat, kind, Supported)
	}
	return fmt.Errorf("%w: C2paSeal supports %s only", ErrUnsupportedFormat, Supported)
}

// Describe names a common file format that C2paSeal does not support, from
// the file's leading bytes ("an MP4 video", "a PDF document", ...), or
// returns "" if it does not recognise the file. Supported formats also give
// "".
func Describe(b []byte) string {
	switch {
	case len(b) == 0:
		return "an empty file"
	case Detect(b) != "":
		return ""
	case len(b) >= 12 && string(b[4:8]) == "ftyp":
		return describeBMFF(string(b[8:12]))
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "a GIF image"
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "a PDF document"
	case bytes.HasPrefix(b, []byte("II*\x00")), bytes.HasPrefix(b, []byte("MM\x00*")):
		return "a TIFF image (or a camera raw file such as DNG)"
	case bytes.HasPrefix(b, []byte("BM")) && len(b) >= 14 && int(binary.LittleEndian.Uint32(b[2:6])) == len(b):
		return "a BMP image"
	case bytes.HasPrefix(b, []byte{0xFF, 0x0A}), bytes.HasPrefix(b, []byte("\x00\x00\x00\x0cJXL \r\n\x87\n")):
		return "a JPEG XL image"
	case len(b) >= 12 && string(b[0:4]) == "RIFF":
		switch string(b[8:12]) {
		case "WAVE":
			return "a WAV audio file"
		case "AVI ":
			return "an AVI video"
		}
		return "a RIFF file other than WebP"
	case bytes.HasPrefix(b, []byte("ID3")), len(b) >= 2 && b[0] == 0xFF && b[1]&0xE0 == 0xE0:
		return "an MP3 audio file"
	case bytes.HasPrefix(b, []byte("fLaC")):
		return "a FLAC audio file"
	case bytes.HasPrefix(b, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		return "a Matroska or WebM video"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return "a ZIP archive (or a document format built on ZIP)"
	case isSVG(b):
		return "an SVG image"
	}
	return ""
}

// describeBMFF names an ISO BMFF file by its major brand: videos and other
// files that share HEIC's and AVIF's container.
func describeBMFF(brand string) string {
	switch brand {
	case "qt  ":
		return "a QuickTime (MOV) video"
	case "M4A ", "M4B ":
		return "an M4A audio file"
	case "3gp4", "3gp5", "3gp6", "3g2a":
		return "a 3GP video"
	case "crx ":
		return "a Canon CR3 raw image"
	}
	return "an MP4 video (or another ISO BMFF file that is not HEIC or AVIF)"
}

// isSVG reports whether b starts, after an optional BOM, XML declaration and
// comments, with an <svg element.
func isSVG(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
	head := b[:min(len(b), 1024)]
	i := bytes.Index(head, []byte("<svg"))
	if i < 0 {
		return false
	}
	before := bytes.TrimSpace(head[:i])
	return len(before) == 0 || bytes.HasPrefix(before, []byte("<?xml")) || bytes.HasPrefix(before, []byte("<!--")) || bytes.HasPrefix(before, []byte("<!DOCTYPE"))
}
