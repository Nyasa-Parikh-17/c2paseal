package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
)

// server is the manifest store's HTTP API:
//
//	PUT /v1/manifests/{id}   store a manifest store (API key; the store's
//	                         soft binding must carry {id})
//	GET /v1/manifests/{id}   fetch it (no key; CORS open, for the web app)
//	GET /healthz
type server struct {
	store    *fileStore
	keys     map[[sha256.Size]byte]string // hash → name
	maxBytes int64
	audit    *slog.Logger
	version  string
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/manifests/{id}", s.get)
	mux.HandleFunc("PUT /v1/manifests/{id}", s.put)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"status\":\"ok\",\"version\":%q}\n", s.version)
	})
	return mux
}

func (s *server) get(w http.ResponseWriter, r *http.Request) {
	// Lookups are public by design: anyone holding a copy of the image can
	// read its ID, and the IDs are random 64-bit values.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	id, err := watermark.ParseID(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusBadRequest, "the ID must be 16 hex digits")
		return
	}
	b, err := s.store.get(id)
	if errors.Is(err, errNotFound) {
		s.log(r, http.StatusNotFound, "", id, nil)
		fail(w, http.StatusNotFound, errNotFound.Error())
		return
	}
	if err != nil {
		s.log(r, http.StatusInternalServerError, "", id, err)
		fail(w, http.StatusInternalServerError, "could not read the store")
		return
	}
	w.Header().Set("Content-Type", "application/c2pa")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(b)
	s.log(r, http.StatusOK, "", id, nil)
}

func (s *server) put(w http.ResponseWriter, r *http.Request) {
	name := s.keyName(r)
	if name == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sealstore"`)
		s.log(r, http.StatusUnauthorized, "", 0, nil)
		fail(w, http.StatusUnauthorized, "missing or unknown API key")
		return
	}
	id, err := watermark.ParseID(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusBadRequest, "the ID must be 16 hex digits")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body over %d bytes", s.maxBytes))
			return
		}
		fail(w, http.StatusBadRequest, "could not read the body")
		return
	}
	// The store must be one this ID belongs to: its active manifest
	// records the ID as its watermark soft binding. That keeps the store
	// from holding someone else's credentials under an unrelated ID.
	got, err := softBindingID(body)
	if err != nil || got != id {
		why := fmt.Sprintf("the store's soft binding does not carry %s", id)
		if err != nil {
			why = err.Error()
		}
		s.log(r, http.StatusUnprocessableEntity, name, id, errors.New(why))
		fail(w, http.StatusUnprocessableEntity, why)
		return
	}
	replaced, err := s.store.put(id, body)
	if err != nil {
		s.log(r, http.StatusInternalServerError, name, id, err)
		fail(w, http.StatusInternalServerError, "could not save the store")
		return
	}
	code := http.StatusCreated
	if replaced {
		code = http.StatusOK
	}
	s.log(r, code, name, id, nil, slog.Int("bytes", len(body)), slog.Bool("replaced", replaced))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, "{\"id\":%q,\"replaced\":%v}\n", id.String(), replaced)
}

// keyName returns the name of the API key in the Authorization header, or
// "". Every stored hash is compared in constant time.
func (s *server) keyName(r *http.Request) string {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return ""
	}
	h := sha256.Sum256([]byte(token))
	name := ""
	for k, n := range s.keys {
		if subtle.ConstantTimeCompare(h[:], k[:]) == 1 {
			name = n
		}
	}
	return name
}

func (s *server) log(r *http.Request, status int, key string, id watermark.ID, err error, extra ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("method", r.Method), slog.String("path", r.URL.Path),
		slog.String("remote_addr", r.RemoteAddr), slog.Int("status", status),
	}
	if id != 0 {
		attrs = append(attrs, slog.String("watermark_id", id.String()))
	}
	if key != "" {
		attrs = append(attrs, slog.String("api_key", key))
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	level := slog.LevelInfo
	if status >= 400 {
		level = slog.LevelWarn
	}
	s.audit.LogAttrs(context.Background(), level, "request", append(attrs, extra...)...)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"error": msg})
	w.Write(append(b, '\n'))
}

// parseKeys reads an API key file: "<name> <sha256 hex of the key>" per
// line, # comments allowed (the format sealsvc uses, without options).
func parseKeys(r io.Reader) (map[[sha256.Size]byte]string, error) {
	keys := map[[sha256.Size]byte]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return nil, fmt.Errorf("api keys line %d: want <name> <sha256 hex>", n)
		}
		h, err := hex.DecodeString(f[1])
		if err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("api keys line %d: %q is not a SHA-256 hex digest", n, f[1])
		}
		keys[[sha256.Size]byte(h)] = f[0]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("api keys: no keys")
	}
	return keys, nil
}

// newHTTPServer wraps h with the timeouts a public service needs.
func newHTTPServer(h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}
