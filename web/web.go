// Package web serves the C2paSeal demo app: drop an image, see its manifest
// store and validation statuses, sign it with the TEST ONLY PKI and see the
// re-verified result.
//
// The app is the static site in site/, the same one deployed to GitHub
// Pages. There it runs the library as WebAssembly; served from here it has
// no c2paseal.wasm and uses this package's HTTP API instead, which returns
// the same JSON (package internal/analysis builds it for both).
package web

import (
	"crypto"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/analysis"
)

//go:embed site
var siteFS embed.FS

// Site is the static web app: index.html, its script, style and service
// worker, and the TEST ONLY demo PKI and sample image under demo/. Deploying
// it needs c2paseal.wasm and wasm_exec.js next to index.html (see the pages
// workflow); without them the app uses the HTTP API of Handler.
func Site() fs.FS {
	sub, err := fs.Sub(siteFS, "site")
	if err != nil {
		panic(err) // the embedded directory is always there
	}
	return sub
}

// ContentSecurityPolicy is sent with every page and also set in
// index.html's meta tag, for hosts that cannot send headers (GitHub Pages).
// 'wasm-unsafe-eval' lets the page compile c2paseal.wasm and nothing else.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'"

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
type Analysis = analysis.Analysis

// StatusView is one validation status for display.
type StatusView = analysis.StatusView

// SignedFile is a file the demo signed, returned inline.
type SignedFile = analysis.SignedFile

// Handler returns the demo's HTTP handler:
//
//	GET  /            the static site (Site), index.html at /
//	POST /api/verify  analyse an uploaded file (multipart field "file")
//	POST /api/sign    sign it with the test PKI and analyse the result
//
// Both POST endpoints take an optional form field trust=1 to trust the test
// root.
func Handler(cfg *Config) http.Handler {
	mux := http.NewServeMux()
	static := http.FileServerFS(Site())
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		static.ServeHTTP(w, r)
	})
	mux.HandleFunc("POST /api/verify", func(w http.ResponseWriter, r *http.Request) {
		name, b, trust, err := upload(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, analysis.Analyse(name, b, trustAnchors(cfg, trust)))
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
		out := analysis.SignedName(name)
		a := analysis.Analyse(out, signed, trustAnchors(cfg, trust))
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
