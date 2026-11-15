// Package middleware signs uploaded images with C2PA Content Credentials
// before an http.Handler sees them.
//
// Wrap an upload handler with [Sign]. Each image in the request is replaced
// by its signed copy:
//   - a file part of a multipart/form-data request;
//   - or the whole body of a request whose Content-Type is image/*.
//
// The images can be JPEG, PNG, WebP, HEIC or AVIF. The handler then reads
// the request as usual (r.FormFile, r.Body, ...) and gets the signed bytes.
// [Files] says what was signed.
//
// The signing key can be a file, or a KMS key named by a URI through
// [sign.OpenKey] (the keys/awskms and keys/gcpkms modules register the
// awskms: and gcpkms: schemes):
//
//	key, err := sign.OpenKey(ctx, "awskms:arn:aws:kms:…")
//	chain, err := c2paseal.LoadChain("chain.pem")
//	mw, err := middleware.Sign(middleware.Config{
//		Options: &sign.Options{Chain: chain, Signer: key},
//	})
//	http.Handle("POST /upload", mw(uploadHandler))
//
// The whole request body is read into memory, up to Config.MaxBytes.
// Signing an image that already has Content Credentials keeps them and
// records them as the parent ingredient, as [sign.Asset] does.
package middleware

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

// DefaultMaxBytes is the request body limit when Config.MaxBytes is zero.
const DefaultMaxBytes = 32 << 20

// ErrUnsupported is the error passed to Config.ErrorHandler when
// Config.RejectUnsupported is set and an upload is not an image the signer
// supports.
var ErrUnsupported = errors.New("middleware: not a JPEG, PNG, WebP, HEIC or AVIF image")

// Config configures [Sign].
type Config struct {
	// Options is the signing configuration; Chain and Signer are required.
	// Each file is signed with its own shallow copy.
	Options *sign.Options

	// Prepare, if set, is called before each file is signed, with that
	// file's copy of Options: to set the title from the file name, for
	// example. Copy a slice before changing it; the copies share Options'
	// slices. An error rejects the request with 400 Bad Request.
	Prepare func(r *http.Request, f *File, o *sign.Options) error

	// Fields limits signing to these multipart form fields; nil means
	// every file part.
	Fields []string

	// MaxBytes is the largest request body accepted; zero means
	// DefaultMaxBytes. A larger body gets 413 Request Entity Too Large.
	MaxBytes int64

	// RejectUnsupported makes an upload that is not a supported image fail
	// with 415 Unsupported Media Type. By default it is passed through
	// unsigned.
	RejectUnsupported bool

	// ErrorHandler writes the response when a request is rejected; nil
	// means http.Error with a short message. Status codes:
	//   - 400: a malformed multipart body, or a Prepare error;
	//   - 413: the body is too large;
	//   - 415: an unsupported upload, with RejectUnsupported;
	//   - 422: an image that cannot be signed (a corrupt file, for example);
	//   - 500: the signer or the time-stamp authority failed.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, err error)
}

// File describes one upload that the middleware looked at.
type File struct {
	// Field is the multipart form field; empty for a whole-body upload.
	Field string
	// Filename is the multipart file name; empty for a whole-body upload.
	Filename string
	// Format is c2paseal.FormatJPEG, FormatPNG, ...; empty if the upload
	// is not a supported image.
	Format string
	// Signed reports whether the upload was replaced by a signed copy.
	Signed bool
	// Parent reports whether the upload already had Content Credentials,
	// recorded as the parent ingredient.
	Parent bool
	// Size is the upload's size in bytes after signing.
	Size int
}

type filesKey struct{}

// Files returns the uploads the middleware looked at, in request order, or
// nil if it did not handle the request (no image content type, or a
// request outside the middleware).
func Files(r *http.Request) []File {
	f, _ := r.Context().Value(filesKey{}).([]File)
	return f
}

// Sign returns middleware that signs the images in each request before
// passing it to the next handler. It fails if cfg has no signing
// certificate or key.
func Sign(cfg Config) (func(http.Handler) http.Handler, error) {
	if cfg.Options == nil || len(cfg.Options.Chain) == 0 || cfg.Options.Signer == nil {
		return nil, fmt.Errorf("middleware: %w", sign.ErrNoSigner)
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(w http.ResponseWriter, r *http.Request, status int, err error) {
			msg := http.StatusText(status)
			if status < 500 {
				msg += ": " + err.Error()
			}
			http.Error(w, msg, status)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			switch {
			case err != nil:
				next.ServeHTTP(w, r)
			case ct == "multipart/form-data":
				cfg.multipart(w, r, params["boundary"], next)
			case strings.HasPrefix(ct, "image/"):
				cfg.whole(w, r, next)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}, nil
}

// rejection is a request the middleware refuses.
type rejection struct {
	status int
	err    error
}

func (e *rejection) Error() string { return e.err.Error() }

func (cfg *Config) fail(w http.ResponseWriter, r *http.Request, err error) {
	var rj *rejection
	if !errors.As(err, &rj) {
		rj = &rejection{http.StatusInternalServerError, err}
	}
	cfg.ErrorHandler(w, r, rj.status, rj.err)
}

// read reads the whole body, up to MaxBytes.
func (cfg *Config) read(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cfg.MaxBytes))
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			return nil, &rejection{http.StatusRequestEntityTooLarge, fmt.Errorf("body larger than %d bytes", cfg.MaxBytes)}
		}
		return nil, &rejection{http.StatusBadRequest, fmt.Errorf("read body: %w", err)}
	}
	return b, nil
}

// whole signs a request whose body is the image.
func (cfg *Config) whole(w http.ResponseWriter, r *http.Request, next http.Handler) {
	b, err := cfg.read(w, r)
	if err != nil {
		cfg.fail(w, r, err)
		return
	}
	f := File{}
	out, err := cfg.signFile(r, &f, b)
	if err != nil {
		cfg.fail(w, r, err)
		return
	}
	next.ServeHTTP(w, withBody(r, []File{f}, out, r.Header.Get("Content-Type")))
}

// multipart signs the file parts of a multipart/form-data request and
// passes on a rebuilt body. Other parts are copied byte for byte.
func (cfg *Config) multipart(w http.ResponseWriter, r *http.Request, boundary string, next http.Handler) {
	if boundary == "" {
		cfg.fail(w, r, &rejection{http.StatusBadRequest, errors.New("multipart body without a boundary")})
		return
	}
	b, err := cfg.read(w, r)
	if err != nil {
		cfg.fail(w, r, err)
		return
	}
	mr := multipart.NewReader(bytes.NewReader(b), boundary)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	files := []File{}
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			cfg.fail(w, r, &rejection{http.StatusBadRequest, fmt.Errorf("malformed multipart body: %w", err)})
			return
		}
		data, err := io.ReadAll(p)
		if err != nil {
			cfg.fail(w, r, &rejection{http.StatusBadRequest, fmt.Errorf("malformed multipart body: %w", err)})
			return
		}
		if p.FileName() != "" && cfg.wants(p.FormName()) {
			f := File{Field: p.FormName(), Filename: p.FileName()}
			data, err = cfg.signFile(r, &f, data)
			if err != nil {
				cfg.fail(w, r, err)
				return
			}
			files = append(files, f)
		}
		pw, err := mw.CreatePart(p.Header)
		if err != nil {
			cfg.fail(w, r, err)
			return
		}
		pw.Write(data) // a bytes.Buffer write cannot fail
	}
	if err := mw.Close(); err != nil {
		cfg.fail(w, r, err)
		return
	}
	next.ServeHTTP(w, withBody(r, files, body.Bytes(), mw.FormDataContentType()))
}

func (cfg *Config) wants(field string) bool {
	if cfg.Fields == nil {
		return true
	}
	for _, f := range cfg.Fields {
		if f == field {
			return true
		}
	}
	return false
}

// signFile signs one upload and fills in f. An upload that is not a
// supported image is returned as it is, unless RejectUnsupported is set.
func (cfg *Config) signFile(r *http.Request, f *File, b []byte) ([]byte, error) {
	f.Format = c2paseal.DetectFormat(b)
	f.Size = len(b)
	if f.Format == "" {
		if cfg.RejectUnsupported {
			name := "the body"
			if f.Filename != "" {
				name = strconv.Quote(f.Filename)
			}
			return nil, &rejection{http.StatusUnsupportedMediaType, fmt.Errorf("%s: %w", name, ErrUnsupported)}
		}
		return b, nil
	}
	o := *cfg.Options
	o.Sidecar = false
	if cfg.Prepare != nil {
		if err := cfg.Prepare(r, f, &o); err != nil {
			return nil, &rejection{http.StatusBadRequest, err}
		}
	}
	ws := &watchedSigner{Signer: o.Signer}
	o.Signer = ws
	s, err := sign.Asset(b, &o)
	if err != nil {
		if ws.failed() || errors.Is(err, sign.ErrTimestamp) || errors.Is(err, sign.ErrBadOCSP) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("middleware: sign: %w", err)
		}
		return nil, &rejection{http.StatusUnprocessableEntity, err}
	}
	f.Signed, f.Parent, f.Size = true, s.Parent, len(s.File)
	return s.File, nil
}

// watchedSigner records whether the key itself failed, which is a server
// problem (500) rather than a bad upload (422).
type watchedSigner struct {
	crypto.Signer
	mu  sync.Mutex
	err error
}

func (s *watchedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.Signer.Sign(rand, digest, opts)
	if err != nil {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
	}
	return sig, err
}

func (s *watchedSigner) failed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err != nil
}

// withBody returns r with a new body and the files in its context.
func withBody(r *http.Request, files []File, body []byte, contentType string) *http.Request {
	r2 := r.WithContext(context.WithValue(r.Context(), filesKey{}, files))
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	r2.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	r2.Header = r.Header.Clone()
	r2.Header.Set("Content-Type", contentType)
	r2.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r2.TransferEncoding = nil
	r2.MultipartForm, r2.PostForm, r2.Form = nil, nil, nil
	return r2
}
