package assertion

import (
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// FuzzDecode parses a JUMBF tree and decodes every superbox in it as an
// assertion. Decode never fails: unknown or malformed content is kept raw.
func FuzzDecode(f *testing.F) {
	for _, b := range fixtures.SignedFiles() {
		if _, root, err := asset.Extract(b); err == nil {
			if a := root.Find("c2pa.assertions"); a != nil {
				f.Add(a.Bytes())
			}
			f.Add(root.Bytes())
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		root, err := jumbf.Parse(b)
		if err != nil {
			return
		}
		var walk func(b *jumbf.Box, depth int)
		walk = func(b *jumbf.Box, depth int) {
			_ = Decode(b)
			_ = BaseLabel(b.Label())
			for _, c := range b.Contents() {
				if c.IsSuperbox() {
					walk(c, depth+1)
				}
			}
		}
		walk(root, 0)
	})
}
