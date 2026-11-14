package verify

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// TestNegativeSet checks the negative fixture set: every defect class has a
// fixture, and each one is rejected both by C2paSeal and by c2patool (the
// oracle reports Invalid with the expected failure, or refuses the file).
//
// Files are checked in the trusted mode: with the test root trusted, the
// only failures left are the defect itself, and the stapled OCSP answer in
// ocsp/revoked.jpg is only believed when its responder is trusted.
func TestNegativeSet(t *testing.T) {
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	anchors := testAnchors(t)
	tests := []struct {
		defect string
		file   string
		code   string // failure C2paSeal must report
		// refused: c2patool exits with an error instead of a report.
		refused bool
	}{
		{"tampered pixels", "broken/data-flip.jpg", AssertionDataHashMismatch, false},
		{"tampered pixels", "broken/data-flip.png", AssertionDataHashMismatch, false},
		{"bad signature", "broken/sig-flip.jpg", ClaimSignatureMismatch, false},
		{"bad signature", "broken/sig-flip.png", ClaimSignatureMismatch, false},
		{"truncated manifest", "broken/truncated-app11.jpg", "", true},
		{"truncated manifest", "broken/truncated-cabx.png", "", true},
		{"expired certificate", "broken/expired.jpg", SigningCredentialExpired, false},
		{"wrong hash", "broken/wrong-hash.jpg", AssertionDataHashMismatch, false},
		{"wrong hash", "broken/wrong-hash.png", AssertionDataHashMismatch, false},
		{"revoked certificate", "ocsp/revoked.jpg", SigningCredentialRevoked, true},
		{"tampered pixels", "broken/data-flip.webp", AssertionDataHashMismatch, false},
		{"bad signature", "broken/sig-flip.webp", ClaimSignatureMismatch, false},
		{"truncated manifest", "broken/truncated-c2pa.webp", "", true},
		{"wrong hash", "broken/wrong-hash.webp", AssertionDataHashMismatch, false},
	}
	for _, tt := range tests {
		t.Run(tt.defect+"/"+tt.file, func(t *testing.T) {
			path := filepath.Join(dir, filepath.FromSlash(tt.file))
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			kind := fixtures.Broken
			if filepath.Dir(tt.file) == "ocsp" {
				kind = fixtures.OCSP
			}
			opts := &Options{TrustAnchors: anchors, Now: corpusTimeFor(fixtures.Fixture{Kind: kind})}
			r := File(b, opts)
			if r.State() != Invalid {
				t.Errorf("C2paSeal: state %s, want Invalid", r.State())
			}
			if tt.code != "" && !slices.ContainsFunc(r.Statuses(), func(s Status) bool {
				return s.Code == tt.code && s.Kind() == Failure
			}) {
				t.Errorf("C2paSeal: no %s failure in %q", tt.code, render(r.Statuses()))
			}

			exp, err := fixtures.Fixture{TrustedPath: path + ".trusted.expected.json"}.Trusted()
			if err != nil {
				t.Fatal(err)
			}
			if tt.refused {
				if !exp.Failed() {
					t.Errorf("c2patool: state %s, want it to refuse the file", exp.ValidationState)
				}
				return
			}
			if exp.Failed() || exp.ValidationState != "Invalid" {
				t.Errorf("c2patool: state %q (error %q), want Invalid", exp.ValidationState, exp.C2patoolError)
			}
			if !slices.Contains(renderOracle(exp.ValidationResults.ActiveManifest), "failure: "+tt.code+" @"+urlOf(r, tt.code)) {
				t.Errorf("c2patool: no %s failure in %q", tt.code, renderOracle(exp.ValidationResults.ActiveManifest))
			}
		})
	}
}

// urlOf returns the URL C2paSeal logged with its first status code.
func urlOf(r *Result, code string) string {
	for _, s := range r.Statuses() {
		if s.Code == code {
			return s.URL
		}
	}
	return ""
}
