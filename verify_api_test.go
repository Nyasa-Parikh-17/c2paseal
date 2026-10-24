package c2paseal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func TestVerify(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := LoadTrustAnchors(filepath.Join(dir, "pki", "trust-anchors.pem"))
	if err != nil || len(anchors) != 1 {
		t.Fatalf("LoadTrustAnchors: %v, %d certs", err, len(anchors))
	}
	tests := []struct {
		file string
		opts *VerifyOptions
		want verify.State
	}{
		{"signed/small.jpg", nil, verify.Valid},
		{"signed/small.jpg", &VerifyOptions{TrustAnchors: anchors}, verify.Trusted},
		{"broken/data-flip.png", nil, verify.Invalid},
		{"no-such-file.jpg", nil, verify.Invalid},
	}
	for _, tt := range tests {
		path := filepath.Join(dir, tt.file)
		if got := VerifyFile(path, tt.opts).State(); got != tt.want {
			t.Errorf("%s: %s, want %s", tt.file, got, tt.want)
		}
		if len(Verify(path, tt.opts)) == 0 {
			t.Errorf("%s: Verify returned no statuses", tt.file)
		}
	}
}

func TestLoadTrustAnchorsErrors(t *testing.T) {
	tmp := t.TempDir()
	notPEM := filepath.Join(tmp, "x.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	badCert := filepath.Join(tmp, "bad.pem")
	if err := os.WriteFile(badCert, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(tmp, "missing.pem"), notPEM, badCert} {
		if _, err := LoadTrustAnchors(p); err == nil {
			t.Errorf("LoadTrustAnchors(%s) succeeded", filepath.Base(p))
		}
	}
}
