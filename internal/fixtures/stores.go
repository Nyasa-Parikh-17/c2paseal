package fixtures

import (
	"os"
	"path/filepath"
)

// SignedFiles returns the bytes of every signed fixture, for
// seeding fuzz corpora. Errors give an empty list: seeds are optional.
func SignedFiles() [][]byte {
	fs, err := ListKind(Signed)
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, f := range fs {
		if b, err := os.ReadFile(filepath.Clean(f.Path)); err == nil {
			out = append(out, b)
		}
	}
	return out
}
