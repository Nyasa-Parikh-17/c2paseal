// Package web serves the C2paSeal web app at /app/: drop an image, see its
// manifest store and validation statuses, sign it with the TEST ONLY PKI and
// see the re-verified result.
//
// The app is the static site in site/app. The C2paSeal website (its own
// repository, at WebsiteURL) publishes the same files with the library
// compiled to WebAssembly. Served from here the app has no c2paseal.wasm and
// uses this package's HTTP API instead, which returns the same JSON (package
// internal/analysis builds it for both).
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
	"path"
	"path/filepath"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/analysis"
)

//go:embed site
var siteFS embed.FS

// WebsiteURL is the C2paSeal website, which has the home page and the
// documentation (at docs/) and publishes this app at app/.
const WebsiteURL = "https://nyasa-parikh-17.github.io/c2paseal-website/"

// Site is the embedded site: the app under app/ (see App).
func Site() fs.FS {
	sub, err := fs.Sub(siteFS, "site")
	if err != nil {
		panic(err) // the embedded directory is always there
	}
	return sub
}

// App is the web app, Site's app/ folder: index.html, its script, style and
// service worker, and the TEST ONLY demo PKI and sample image under demo/.
// Deploying it needs c2paseal.wasm and wasm_exec.js next to its index.html
// (see the pages workflow); without them the app uses the HTTP API of
// Handler.
func App() fs.FS {
	sub, err := fs.Sub(siteFS, "site/app")
	if err != nil {
		panic(err)
	}
	return sub
}

// siteTypes fixes the Content-Type of the site's files. Without it,
// net/http takes types from the operating system, which differ (Windows
// can map .js to application/javascript).
var siteTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".svg":  "image/svg+xml",
	".jpg":  "image/jpeg",
	".pem":  "text/plain; charset=utf-8",
	".key":  "text/plain; charset=utf-8",
}

// ContentSecurityPolicy is sent with every page and also set in
// index.html's meta tag, for hosts that cannot send headers (GitHub Pages).
// 'wasm-unsafe-eval' lets the page compile c2paseal.wasm and nothing else.
// connect-src allows https: and localhost so "Recover credentials" can
// fetch from the manifest store the user names.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self' https: http://localhost:* http://127.0.0.1:*; worker-src 'self'; base-uri 'none'; form-action 'none'"

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
//	GET  /app/            the app (App)
//	GET  /                redirects to /app/
//	GET  /docs/…          redirects to the documentation on the website
//	POST /app/api/verify  analyse an uploaded file (multipart field "file")
//	POST /app/api/sign    sign it with the test PKI and analyse the result
//
// Both POST endpoints take optional form fields: trust=1 to trust the test
// root, and anchors, PEM trust anchors (the user's trust list) to trust as
// well.
func Handler(cfg *Config) http.Handler {
	mux := http.NewServeMux()
	static := http.FileServerFS(Site())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusFound)
	})
	mux.HandleFunc("GET /docs/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, WebsiteURL+strings.TrimPrefix(r.URL.Path, "/"), http.StatusFound)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if ct, ok := siteTypes[path.Ext(r.URL.Path)]; ok {
			w.Header().Set("Content-Type", ct)
		}
		static.ServeHTTP(w, r)
	})
	mux.HandleFunc("POST /app/api/verify", func(w http.ResponseWriter, r *http.Request) {
		name, b, anchors, err := upload(w, r, cfg)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, analysis.Analyse(name, b, anchors))
	})
	mux.HandleFunc("POST /app/api/sign", func(w http.ResponseWriter, r *http.Request) {
		if cfg == nil || cfg.Signer == nil {
			writeError(w, http.StatusServiceUnavailable, errors.New("no signing key configured"))
			return
		}
		name, b, anchors, err := upload(w, r, cfg)
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
		a := analysis.Analyse(out, signed, anchors)
		a.Signed = &SignedFile{Name: out, Data: signed}
		writeJSON(w, a)
	})
	return mux
}

// upload reads the multipart "file" field, and the trust anchors to use:
// the test root with trust=1, plus any PEM in the "anchors" field.
func upload(w http.ResponseWriter, r *http.Request, cfg *Config) (string, []byte, []*x509.Certificate, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload+1<<20)
	if err := r.ParseMultipartForm(MaxUpload); err != nil {
		return "", nil, nil, fmt.Errorf("read upload: %w", err)
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		return "", nil, nil, fmt.Errorf("no file uploaded: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxUpload+1))
	if err != nil {
		return "", nil, nil, fmt.Errorf("read upload: %w", err)
	}
	if len(b) > MaxUpload {
		return "", nil, nil, fmt.Errorf("file larger than %d MB", MaxUpload>>20)
	}
	var anchors []*x509.Certificate
	if r.FormValue("trust") == "1" && cfg != nil {
		anchors = append(anchors, cfg.Anchors...)
	}
	if pem := r.FormValue("anchors"); pem != "" {
		user, err := c2paseal.ParseTrustAnchors([]byte(pem))
		if err != nil {
			return "", nil, nil, fmt.Errorf("your trust list: %w", err)
		}
		anchors = append(anchors, user...)
	}
	return filepath.Base(h.Filename), b, anchors, nil
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
