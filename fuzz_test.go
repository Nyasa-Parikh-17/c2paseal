package c2paseal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// FuzzReadStore checks that reading a manifest store kept outside the file
// (a sidecar or a downloaded remote store) never panics.
func FuzzReadStore(f *testing.F) {
	if dir, err := fixtures.Dir(); err == nil {
		paths, _ := filepath.Glob(filepath.Join(dir, "remote", "*.c2pa"))
		served, _ := filepath.Glob(filepath.Join(dir, "remote", "served", "*"))
		for _, p := range append(paths, served...) {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := ReadStore(b)
		if err == nil && st == nil {
			t.Fatal("nil store without an error")
		}
	})
}

// FuzzTrustFiles checks that the trust anchor, allowed list and trust
// configuration parsers never panic.
func FuzzTrustFiles(f *testing.F) {
	if dir, err := fixtures.Dir(); err == nil {
		for _, name := range []string{"pki/trust-anchors.pem", "pki/leaf-chain.pem"} {
			if b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name))); err == nil {
				f.Add(b)
			}
		}
		trust, _ := filepath.Glob(filepath.Join(dir, "trust", "*"))
		for _, p := range trust {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
	}
	f.Add([]byte("1.3.6.1.5.5.7.3.36\n// comment\n1.3.6.1.4.1.311.76.59.1.9\n"))
	f.Add([]byte("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseTrustAnchors(b, "fuzz")
		if h, err := parseAllowedList(b, "fuzz"); err == nil && len(h) == 0 {
			t.Fatal("empty allowed list without an error")
		}
		for _, oid := range parseTrustConfig(b) {
			if len(oid) < 2 {
				t.Fatalf("OID %v has fewer than two arcs", oid)
			}
		}
	})
}
