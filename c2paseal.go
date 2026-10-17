package c2paseal

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/container/png"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

// Supported file formats.
const (
	FormatJPEG = "jpeg"
	FormatPNG  = "png"
)

// ErrUnsupportedFormat is returned for files that are neither JPEG nor PNG.
var ErrUnsupportedFormat = errors.New("c2paseal: unsupported file format")

// ManifestStore is the decoded C2PA manifest store of a file. Reading does
// not verify anything; hashed-URI results are recorded in each manifest's
// HashChecks.
type ManifestStore struct {
	Format    string // FormatJPEG or FormatPNG
	Root      *jumbf.Box
	Manifests []*manifest.Manifest // in store order
	Active    *manifest.Manifest   // the last manifest
}

// Read reads and decodes the manifest store embedded in a JPEG or PNG file.
func Read(path string) (*ManifestStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: %w", err)
	}
	return ReadBytes(b)
}

// ReadBytes is Read for a file already in memory. The store shares memory
// with b.
func ReadBytes(b []byte) (*ManifestStore, error) {
	format := DetectFormat(b)
	var root *jumbf.Box
	switch format {
	case FormatJPEG:
		st, err := jpeg.Extract(b)
		if err != nil {
			return nil, fmt.Errorf("c2paseal: %w", err)
		}
		root = st.Root
	case FormatPNG:
		st, err := png.Extract(b)
		if err != nil {
			return nil, fmt.Errorf("c2paseal: %w", err)
		}
		root = st.Root
	default:
		return nil, ErrUnsupportedFormat
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: %w", err)
	}
	return &ManifestStore{Format: format, Root: root, Manifests: ms, Active: ms[len(ms)-1]}, nil
}

// DetectFormat returns FormatJPEG or FormatPNG from a file's leading bytes,
// or "" if it is neither.
func DetectFormat(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8}):
		return FormatJPEG
	case bytes.HasPrefix(b, []byte(png.Signature)):
		return FormatPNG
	}
	return ""
}
