package verify

import (
	"os"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/manifest"
)

// FuzzToken parses arbitrary bytes as an RFC 3161 token and runs the
// per-signer checks on it; malformed tokens must give errors or statuses,
// never a panic. Seeds are the real tokens in the corpus (DigiCert, Adobe).
func FuzzToken(f *testing.F) {
	all, _ := fixtures.List()
	for _, fx := range all {
		b, err := os.ReadFile(fx.Path)
		if err != nil {
			continue
		}
		_, root, err := asset.Extract(b)
		if err != nil {
			continue
		}
		ms, err := manifest.DecodeStore(root)
		if err != nil {
			continue
		}
		for _, m := range ms {
			if m.Signature != nil {
				for _, ts := range m.Signature.Timestamps {
					f.Add(ts.Token)
				}
			}
		}
	}
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		tok, err := parseToken(b)
		if err != nil {
			return
		}
		for _, s := range tok.signers {
			if c := tok.cert(s); c != nil {
				tok.checkSigner(s, c, []byte("data"))
			}
			s.signingTime()
		}
	})
}
