package c2paseal

import (
	"fmt"
	"os"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

// Supported file formats.
const (
	FormatJPEG = asset.JPEG
	FormatPNG  = asset.PNG
)

// ErrUnsupportedFormat is returned for files that are neither JPEG nor PNG.
var ErrUnsupportedFormat = asset.ErrUnsupportedFormat

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
	format, root, err := asset.Extract(b)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: %w", err)
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: %w", err)
	}
	return &ManifestStore{Format: format, Root: root, Manifests: ms, Active: ms[len(ms)-1]}, nil
}

// DetectFormat returns FormatJPEG or FormatPNG from a file's leading bytes,
// or "" if it is neither.
func DetectFormat(b []byte) string { return asset.Detect(b) }
