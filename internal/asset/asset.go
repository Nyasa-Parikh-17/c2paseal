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
)

// Supported formats.
const (
	JPEG = "jpeg"
	PNG  = "png"
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
