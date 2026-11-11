// Package web serves the C2paSeal demo UI: drop an image, see its manifest
// store and validation statuses, sign it with the TEST ONLY PKI and see the
// re-verified result. All logic is in the library; the embedded page only
// renders the JSON these handlers return.
package web

import (
	"crypto"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

//go:embed index.html
var indexHTML []byte

// MaxUpload is the largest file the demo accepts.
const MaxUpload = 32 << 20

// Config is the demo's signing and trust material.
type Config struct {
	// Chain and Signer sign files for the "Sign" button. They are expected
	// to be the TEST ONLY PKI; the page says so.
	Chain  []*x509.Certificate
	Signer crypto.Signer
	// Anchors are trusted when the page's "trust the test root" box is on.
	Anchors []*x509.Certificate
}

// LoadTestPKI reads leaf-chain.pem, leaf.key and trust-anchors.pem from dir
// (normally testdata/pki).
func LoadTestPKI(dir string) (*Config, error) {
	chain, signer, err := c2paseal.LoadSigner(filepath.Join(dir, "leaf-chain.pem"), filepath.Join(dir, "leaf.key"))
	if err != nil {
		return nil, err
	}
	anchors, err := c2paseal.LoadTrustAnchors(filepath.Join(dir, "trust-anchors.pem"))
	if err != nil {
		return nil, err
	}
	return &Config{Chain: chain, Signer: signer, Anchors: anchors}, nil
}

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

// Handler returns the demo's HTTP handler:
//
//	GET  /            the page
//	POST /api/verify  analyse an uploaded file (multipart field "file")
//	POST /api/sign    sign it with the test PKI and analyse the result
//
// Both POST endpoints take an optional form field trust=1 to trust the test
// root.
func Handler(cfg *Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		w.Write(indexHTML)
	})
	mux.HandleFunc("POST /api/verify", func(w http.ResponseWriter, r *http.Request) {
		name, b, trust, err := upload(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, analyse(name, b, trustAnchors(cfg, trust)))
	})
	mux.HandleFunc("POST /api/sign", func(w http.ResponseWriter, r *http.Request) {
		if cfg == nil || cfg.Signer == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("no signing key configured"))
			return
		}
		name, b, trust, err := upload(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		signed, err := c2paseal.SignBytes(b, &c2paseal.SignOptions{Chain: cfg.Chain, Signer: cfg.Signer, Title: name})
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		out := signedName(name)
		a := analyse(out, signed, trustAnchors(cfg, trust))
		a.Signed = &SignedFile{Name: out, Data: signed}
		writeJSON(w, a)
	})
	return mux
}

func trustAnchors(cfg *Config, trust bool) []*x509.Certificate {
	if !trust || cfg == nil {
		return nil
	}
	return cfg.Anchors
}

// analyse reads and verifies b with the library.
func analyse(name string, b []byte, anchors []*x509.Certificate) *Analysis {
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

// upload reads the multipart "file" field and the "trust" flag.
func upload(w http.ResponseWriter, r *http.Request) (string, []byte, bool, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload+1<<20)
	if err := r.ParseMultipartForm(MaxUpload); err != nil {
		return "", nil, false, fmt.Errorf("read upload: %w", err)
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		return "", nil, false, fmt.Errorf("no file uploaded: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxUpload+1))
	if err != nil {
		return "", nil, false, fmt.Errorf("read upload: %w", err)
	}
	if len(b) > MaxUpload {
		return "", nil, false, fmt.Errorf("file larger than %d MB", MaxUpload>>20)
	}
	return filepath.Base(h.Filename), b, r.FormValue("trust") == "1", nil
}

// signedName turns photo.jpg into photo.signed.jpg.
func signedName(name string) string {
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext) + ".signed" + ext
}

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func writeError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	w.Write(b)
}
