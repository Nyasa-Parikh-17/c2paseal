package sign

import (
	"os"
	"slices"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// FuzzSign signs arbitrary input as JPEG and as PNG, and once more with
// the store in a sidecar and a remote reference in the XMP. Signing must
// never panic, and anything it does sign must verify with no failure other
// than the untrusted test signer. Signed seeds exercise the parent
// ingredient path.
func FuzzSign(f *testing.F) {
	for _, k := range []fixtures.Kind{fixtures.Unsigned, fixtures.Signed} {
		fs, _ := fixtures.ListKind(k)
		for _, fx := range fs {
			if fx.Format == "jpeg" || fx.Format == "png" {
				if b, err := os.ReadFile(fx.Path); err == nil && len(b) < 64<<10 {
					f.Add(b)
				}
			}
		}
	}
	chain, key := testPKI(f)
	opts := &Options{Chain: chain, Signer: key}
	f.Fuzz(func(t *testing.T, b []byte) {
		for name, sign := range map[string]func([]byte, *Options) ([]byte, error){"JPEG": JPEG, "PNG": PNG} {
			out, err := sign(b, opts)
			if err != nil {
				continue
			}
			r := verify.File(out, nil)
			if got := failures(r); !slices.Equal(got, []string{verify.SigningCredentialUntrusted}) {
				t.Fatalf("%s: signed file has failures %q", name, got)
			}
		}
		ext := &Options{Chain: chain, Signer: key, Sidecar: true, RemoteURL: "https://example.com/m.c2pa"}
		if s, err := Asset(b, ext); err == nil {
			r := verify.File(s.File, &verify.Options{ManifestStore: s.Store})
			if got := failures(r); !slices.Equal(got, []string{verify.SigningCredentialUntrusted}) {
				t.Fatalf("sidecar: signed file has failures %q", got)
			}
		}
	})
}
