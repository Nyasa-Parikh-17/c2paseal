package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
)

// fileStore keeps one manifest store per watermark ID, as <dir>/<id>.c2pa.
type fileStore struct {
	dir string
}

var errNotFound = errors.New("no manifest store for this watermark ID")

func (s *fileStore) path(id watermark.ID) string { return filepath.Join(s.dir, id.String()+".c2pa") }

// get returns the store for id, or errNotFound.
func (s *fileStore) get(id watermark.ID) ([]byte, error) {
	b, err := os.ReadFile(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNotFound
	}
	return b, err
}

// put writes the store for id atomically (temporary file, then rename) and
// reports whether it replaced an existing one.
func (s *fileStore) put(id watermark.ID, store []byte) (replaced bool, err error) {
	if _, err := os.Stat(s.path(id)); err == nil {
		replaced = true
	}
	tmp, err := os.CreateTemp(s.dir, ".put-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(store); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return replaced, os.Rename(tmp.Name(), s.path(id))
}

// softBindingID returns the watermark ID that the store's active manifest
// records in a c2pa.soft-binding assertion with this package's algorithm.
func softBindingID(store []byte) (watermark.ID, error) {
	ms, err := c2paseal.ReadStore(store)
	if err != nil {
		return 0, fmt.Errorf("not a manifest store: %w", err)
	}
	for _, a := range ms.Active.Assertions {
		if assertion.BaseLabel(a.Label) != assertion.LabelSoftBinding {
			continue
		}
		sb, ok := a.Value.(*assertion.SoftBinding)
		if !ok || sb.Alg != watermark.SoftBindingAlg {
			continue
		}
		for _, b := range sb.Blocks {
			if id, err := watermark.ParseID(b.Value); err == nil {
				return id, nil
			}
		}
	}
	return 0, fmt.Errorf("the active manifest has no %s soft binding (%s)", assertion.LabelSoftBinding, watermark.SoftBindingAlg)
}
