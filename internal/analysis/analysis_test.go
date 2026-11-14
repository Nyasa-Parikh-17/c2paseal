package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func TestAnalyse(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := c2paseal.LoadTrustAnchors(filepath.Join(dir, "pki", "trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range []struct {
		file    string
		anchors bool
		state   verify.State
		store   bool
		failure string // a failure code that must be listed, with kind "failure"
	}{
		{"signed/small.jpg", false, verify.Valid, true, verify.SigningCredentialUntrusted},
		{"signed/small.png", true, verify.Trusted, true, ""},
		{"broken/data-flip.jpg", true, verify.Invalid, true, verify.AssertionDataHashMismatch},
		{"unsigned/small.png", false, verify.Invalid, false, verify.ClaimMissing},
	} {
		t.Run(tc.file, func(t *testing.T) {
			var a []byte = read(tc.file)
			var an = Analyse(filepath.Base(tc.file), a, nil)
			if tc.anchors {
				an = Analyse(filepath.Base(tc.file), a, anchors)
			}
			if an.State != tc.state || (an.ManifestStore != nil) != tc.store || an.Trusted != tc.anchors || an.Size != len(a) || an.File != filepath.Base(tc.file) {
				t.Errorf("state %s, store %v, trusted %v, size %d, file %q", an.State, an.ManifestStore != nil, an.Trusted, an.Size, an.File)
			}
			if !tc.store && an.ReadError == "" {
				t.Error("no read error for a file without a store")
			}
			found := tc.failure == ""
			for _, s := range an.Statuses {
				if s.Code == tc.failure && s.Kind == "failure" && s.Scope == "active manifest" {
					found = true
				}
			}
			if !found {
				t.Errorf("no %s failure in %+v", tc.failure, an.Statuses)
			}
		})
	}
}

func TestSignedName(t *testing.T) {
	for in, want := range map[string]string{"photo.jpg": "photo.signed.jpg", "a.b.png": "a.b.signed.png", "noext": "noext.signed"} {
		if got := SignedName(in); got != want {
			t.Errorf("SignedName(%q) = %q, want %q", in, got, want)
		}
	}
}
