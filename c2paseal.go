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
	Sidecar   string               // the sidecar file the store came from; empty if embedded
}

// Read reads and decodes the manifest store of a JPEG or PNG file: the
// embedded one, or, if there is none, its sidecar (SidecarPath(path)).
func Read(path string) (*ManifestStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: %w", err)
	}
	if sidecar, ok := findSidecar(path, b, nil); ok {
		st, err := ReadStore(sidecar)
		if err != nil {
			return nil, err
		}
		st.Format, st.Sidecar = asset.Detect(b), SidecarPath(path)
		return st, nil
	}
	return ReadBytes(b)
}

// ReadStore decodes a manifest store on its own: a .c2pa sidecar or a
// fetched remote store. Format is left empty.
func ReadStore(store []byte) (*ManifestStore, error) {
	root, err := jumbf.Parse(store)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: %w", err)
	}
	ms, err := manifest.DecodeStore(root)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: %w", err)
	}
	return &ManifestStore{Root: root, Manifests: ms, Active: ms[len(ms)-1]}, nil
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
