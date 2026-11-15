// Package fixtures finds the C2paSeal repository's test files for the
// examples' tests, which are skipped when the examples are copied elsewhere.
package fixtures

import (
	"os"
	"path/filepath"
	"testing"
)

// Testdata returns the repository's testdata folder, or skips the test.
func Testdata(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p, "pki", "leaf.key")); err != nil {
		t.Skip("C2paSeal's testdata not found (the examples were copied out of the repository)")
	}
	return p
}

// Copy copies a testdata file into dir and returns the copy's path.
func Copy(t *testing.T, td, name, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(td, name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
