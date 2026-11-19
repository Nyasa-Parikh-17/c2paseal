// Package asset detects a file's format and extracts its C2PA manifest
// store, for the read and verify paths.
package asset

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/container/bmff"
	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/container/png"
	"github.com/Nyasa-Parikh-17/c2paseal/container/webp"
	"github.com/Nyasa-Parikh-17/c2paseal/container/xmp"
)

// Supported formats.
const (
	JPEG = "jpeg"
	PNG  = "png"
	WEBP = "webp"
	HEIC = "heic"
	AVIF = "avif"
)

// Errors. Container parse errors are returned wrapped as they are.
var (
	ErrUnsupportedFormat = errors.New("unsupported file format")
	ErrNoManifest        = errors.New("no C2PA manifest store")
	ErrMultipleStores    = errors.New("more than one C2PA manifest store")
)

// Detect returns JPEG, PNG, WEBP, HEIC or AVIF from a file's leading bytes,
// or "".
func Detect(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8}):
		return JPEG
	case bytes.HasPrefix(b, []byte(png.Signature)):
		return PNG
	case webp.IsWebP(b):
		return WEBP
	case bmff.IsBMFF(b):
		return bmffFormat(b)
	}
	return ""
}

// IsImageName reports whether a file name has the extension of a supported
// image: .jpg, .jpeg, .png, .webp, .heic, .heif or .avif, in any case. It
// decides which files of a folder are processed; the format itself is
// always detected from the bytes.
func IsImageName(name string) bool {
	switch strings.ToLower(path.Ext(strings.ReplaceAll(name, "\\", "/"))) {
	case ".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif", ".avif":
		return true
	}
	return false
}

// bmffFormat names an ISO BMFF image by its ftyp brands: AVIF, or HEIC for
// the HEIF/HEVC brands. Other BMFF files (such as MP4) are not supported.
func bmffFormat(b []byte) string {
	major, compat := bmff.Brands(b)
	brands := append([]string{major}, compat...)
	for _, br := range brands {
		if br == "avif" || br == "avis" {
			return AVIF
		}
	}
	for _, br := range brands {
		switch br {
		case "heic", "heix", "heim", "heis", "hevc", "hevx", "mif1", "msf1":
			return HEIC
		}
	}
	return ""
}

// IsBMFF reports whether format is an ISO BMFF one (hard binding
// c2pa.hash.bmff instead of c2pa.hash.data).
func IsBMFF(format string) bool { return format == HEIC || format == AVIF }

// ErrNoXMP is returned when asked to write XMP into a format where that is
// not supported yet.
var ErrNoXMP = errors.New("writing XMP is not supported for this format")

// Extract returns the parsed manifest store of a supported image. A file
// without one gives ErrNoManifest; more than one gives ErrMultipleStores.
func Extract(b []byte) (format string, root *jumbf.Box, err error) {
	format = Detect(b)
	switch format {
	case JPEG:
		st, err := jpeg.Extract(b)
		if err != nil {
			return format, nil, normalize(err, jpeg.ErrNoManifest, jpeg.ErrMultipleStores)
		}
		return format, st.Root, nil
	case PNG:
		st, err := png.Extract(b)
		if err != nil {
			return format, nil, normalize(err, png.ErrNoManifest, png.ErrMultipleStores)
		}
		return format, st.Root, nil
	case WEBP:
		st, err := webp.Extract(b)
		if err != nil {
			return format, nil, normalize(err, webp.ErrNoManifest, webp.ErrMultipleStores)
		}
		return format, st.Root, nil
	case HEIC, AVIF:
		st, err := bmff.Extract(b)
		if err != nil {
			return format, nil, normalize(err, bmff.ErrNoManifest, bmff.ErrMultipleStores)
		}
		return format, st.Root, nil
	}
	return "", nil, ErrUnsupportedFormat
}

// normalize maps a container's own "no manifest" / "multiple stores" errors
// to this package's, keeping the container error in the chain.
func normalize(err, noManifest, multiple error) error {
	switch {
	case errors.Is(err, noManifest):
		return fmt.Errorf("%w: %w", ErrNoManifest, err)
	case errors.Is(err, multiple):
		return fmt.Errorf("%w: %w", ErrMultipleStores, err)
	}
	return err
}

// XMP returns a JPEG's or PNG's XMP packet; ok is false if it has none.
func XMP(b []byte) (packet []byte, ok bool, err error) {
	switch Detect(b) {
	case JPEG:
		p, _, ok, err := jpeg.XMP(b)
		return p, ok, err
	case PNG:
		return png.XMP(b)
	case WEBP:
		return webp.XMP(b)
	case HEIC, AVIF:
		return nil, false, nil // XMP in a BMFF uuid box is not read yet
	}
	return nil, false, ErrUnsupportedFormat
}

// SetXMP returns a copy of a JPEG, PNG or WebP file with its XMP packet
// replaced (or added). HEIC and AVIF give ErrNoXMP.
func SetXMP(b, packet []byte) ([]byte, error) {
	switch Detect(b) {
	case JPEG:
		return jpeg.SetXMP(b, packet)
	case PNG:
		return png.SetXMP(b, packet)
	case WEBP:
		return webp.SetXMP(b, packet)
	case HEIC, AVIF:
		return nil, fmt.Errorf("%w: %s", ErrNoXMP, Detect(b))
	}
	return nil, ErrUnsupportedFormat
}

// RemoteURL returns the dcterms:provenance reference in a file's XMP: the
// URL of a manifest store kept outside the file (C2PA 2.4 §11.5). ok is
// false if there is none.
func RemoteURL(b []byte) (url string, ok bool, err error) {
	packet, ok, err := XMP(b)
	if err != nil || !ok {
		return "", false, err
	}
	return xmp.Provenance(packet)
}

// SetRemoteURL returns a copy of a JPEG, PNG or WebP file whose XMP references url as
// its manifest store, adding an XMP packet if there is none.
func SetRemoteURL(b []byte, url string) ([]byte, error) {
	packet, _, err := XMP(b)
	if err != nil {
		return nil, err
	}
	packet, err = xmp.SetProvenance(packet, url)
	if err != nil {
		return nil, err
	}
	return SetXMP(b, packet)
}
