// Package analysis reads and verifies one file for the demo web app. Both
// the `serve` HTTP API and the WebAssembly build return its JSON, so the
// static site renders the same thing whichever one it talks to. It does not
// import net/http, which would add to the WebAssembly size.
package analysis

import (
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// Analysis is what the page shows for one file.
type Analysis struct {
	File   string `json:"file"`
	Size   int    `json:"size"`
	Format string `json:"format"`
	// ManifestStore is the store as `c2patool --detailed` prints it.
	ManifestStore json.RawMessage `json:"manifest_store,omitempty"`
	ReadError     string          `json:"read_error,omitempty"`
	// Statuses flattens the validation results with each status's kind
	// (success, informational, failure) so the page only has to colour them.
	Statuses []StatusView `json:"statuses"`
	State    verify.State `json:"validation_state"`
	Trusted  bool         `json:"trusted_test_root"`
	Signed   *SignedFile  `json:"signed,omitempty"`
}

// StatusView is one validation status for display.
type StatusView struct {
	Scope       string `json:"scope"` // "active manifest" or the ingredient assertion URI
	Kind        string `json:"kind"`
	Code        string `json:"code"`
	URL         string `json:"url,omitempty"`
	Explanation string `json:"explanation,omitempty"`
}

// SignedFile is a file the demo signed, returned inline.
type SignedFile struct {
	Name string `json:"name"`
	Data []byte `json:"data"` // base64 in JSON
}

// Analyse reads and verifies b with the library. anchors may be nil.
func Analyse(name string, b []byte, anchors []*x509.Certificate) *Analysis {
	a := &Analysis{File: name, Size: len(b), Format: c2paseal.DetectFormat(b), Trusted: anchors != nil}
	if s, err := c2paseal.ReadBytes(b); err != nil {
		a.ReadError = err.Error()
	} else if j, err := json.Marshal(s); err != nil {
		a.ReadError = err.Error()
	} else {
		a.ManifestStore = j
	}
	r := c2paseal.VerifyBytes(b, &c2paseal.VerifyOptions{TrustAnchors: anchors})
	add := func(scope string, ss []verify.Status) {
		for _, s := range ss {
			a.Statuses = append(a.Statuses, StatusView{Scope: scope, Kind: s.Kind().String(), Code: s.Code, URL: s.URL, Explanation: s.Explanation})
		}
	}
	add("active manifest", r.ActiveManifest)
	for _, d := range r.IngredientDeltas {
		add(d.IngredientAssertionURI, d.ValidationDeltas)
	}
	a.State = r.State()
	return a
}

// SignedName turns photo.jpg into photo.signed.jpg.
func SignedName(name string) string {
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext) + ".signed" + ext
}
