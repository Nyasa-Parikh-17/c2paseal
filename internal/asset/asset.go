// Package asset detects a file's format and extracts its C2PA manifest
// store, for the read and verify paths.
package asset

import (
	"bytes"
	"errors"
	"fmt"

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
)

// Errors. Container parse errors are returned wrapped as they are.
var (
	ErrUnsupportedFormat = errors.New("unsupported file format")
	ErrNoManifest        = errors.New("no C2PA manifest store")
	ErrMultipleStores    = errors.New("more than one C2PA manifest store")
)

// Detect returns JPEG or PNG from a file's leading bytes, or "".
func Detect(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8}):
		return JPEG
	case bytes.HasPrefix(b, []byte(png.Signature)):
		return PNG
	case webp.IsWebP(b):
		return WEBP
	}
	return ""
}

// Extract returns the parsed manifest store of a JPEG or PNG. A file
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
	}
	return nil, false, ErrUnsupportedFormat
}

// SetXMP returns a copy of a JPEG or PNG with its XMP packet replaced (or
// added).
func SetXMP(b, packet []byte) ([]byte, error) {
	switch Detect(b) {
	case JPEG:
		return jpeg.SetXMP(b, packet)
	case PNG:
		return png.SetXMP(b, packet)
	case WEBP:
		return webp.SetXMP(b, packet)
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

// SetRemoteURL returns a copy of a JPEG or PNG whose XMP references url as
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
