package middleware_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/middleware"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func testOptions(t *testing.T) *sign.Options {
	t.Helper()
	pki := filepath.Join(signtest.TestdataDir(t), "pki")
	chain, key, err := c2paseal.LoadSigner(filepath.Join(pki, "leaf-chain.pem"), filepath.Join(pki, "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	return &sign.Options{Chain: chain, Signer: key}
}

func anchors(t *testing.T) []*x509.Certificate {
	t.Helper()
	a, err := c2paseal.LoadTrustAnchors(filepath.Join(signtest.TestdataDir(t), "pki", "trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(signtest.TestdataDir(t), "unsigned", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// trusted checks b verifies as Trusted under the TEST ONLY root.
func trusted(t *testing.T, name string, b []byte) {
	t.Helper()
	res := verify.File(b, &verify.Options{TrustAnchors: anchors(t)})
	if res.State() != verify.Trusted {
		t.Errorf("%s: state %v, statuses %v", name, res.State(), res.Statuses())
	}
}

type part struct {
	field, filename, contentType string
	data                         []byte
}

func multipartBody(t *testing.T, parts []part) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		if p.filename != "" {
			h.Set("Content-Disposition", `form-data; name="`+p.field+`"; filename="`+p.filename+`"`)
			h.Set("Content-Type", p.contentType)
		} else {
			h.Set("Content-Disposition", `form-data; name="`+p.field+`"`)
		}
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		pw.Write(p.data)
	}
	w.Close()
	return &buf, w.FormDataContentType()
}

// received is what the wrapped handler saw.
type received struct {
	files  []middleware.File
	form   map[string][]byte // file field → bytes
	values map[string]string
	body   []byte
	called bool
}

func handler(t *testing.T, got *received) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called = true
		got.files = middleware.Files(r)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			if err := r.ParseMultipartForm(64 << 20); err != nil {
				t.Errorf("handler: ParseMultipartForm: %v", err)
				return
			}
			got.form = map[string][]byte{}
			got.values = map[string]string{}
			for k, fhs := range r.MultipartForm.File {
				f, _ := fhs[0].Open()
				got.form[k], _ = io.ReadAll(f)
				f.Close()
			}
			for k, v := range r.MultipartForm.Value {
				got.values[k] = v[0]
			}
		} else {
			got.body, _ = io.ReadAll(r.Body)
			if r.ContentLength != int64(len(got.body)) {
				t.Errorf("ContentLength %d, body %d bytes", r.ContentLength, len(got.body))
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func newMiddleware(t *testing.T, cfg middleware.Config) func(http.Handler) http.Handler {
	t.Helper()
	if cfg.Options == nil {
		cfg.Options = testOptions(t)
	}
	mw, err := middleware.Sign(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return mw
}

func TestMultipart(t *testing.T) {
	jpg, png, webp, heic := fixture(t, "small.jpg"), fixture(t, "small.png"), fixture(t, "small.webp"), fixture(t, "sample.heic")
	body, ct := multipartBody(t, []part{
		{field: "caption", data: []byte("a caption")},
		{field: "photo", filename: "a.jpg", contentType: "image/jpeg", data: jpg},
		{field: "photo2", filename: "b.png", contentType: "image/png", data: png},
		{field: "doc", filename: "notes.txt", contentType: "text/plain", data: []byte("not an image")},
		{field: "photo3", filename: "c.webp", contentType: "image/webp", data: webp},
		{field: "photo4", filename: "d.heic", contentType: "image/heic", data: heic},
	})
	var got received
	mw := newMiddleware(t, middleware.Config{
		Prepare: func(r *http.Request, f *middleware.File, o *sign.Options) error {
			o.Title = f.Filename
			return nil
		},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", ct)
	mw(handler(t, &got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got.values["caption"] != "a caption" {
		t.Errorf("caption %q", got.values["caption"])
	}
	if string(got.form["doc"]) != "not an image" {
		t.Errorf("text file changed: %q", got.form["doc"])
	}
	for _, field := range []string{"photo", "photo2", "photo3", "photo4"} {
		trusted(t, field, got.form[field])
	}
	ms, err := c2paseal.ReadBytes(got.form["photo2"])
	if err != nil {
		t.Fatal(err)
	}
	if title := ms.Active.Claim.Title; title != "b.png" {
		t.Errorf("Prepare's title not used: %q", title)
	}
	want := []middleware.File{
		{Field: "photo", Filename: "a.jpg", Format: c2paseal.FormatJPEG, Signed: true},
		{Field: "photo2", Filename: "b.png", Format: c2paseal.FormatPNG, Signed: true},
		{Field: "doc", Filename: "notes.txt"},
		{Field: "photo3", Filename: "c.webp", Format: c2paseal.FormatWebP, Signed: true},
		{Field: "photo4", Filename: "d.heic", Format: c2paseal.FormatHEIC, Signed: true},
	}
	if len(got.files) != len(want) {
		t.Fatalf("Files: %+v", got.files)
	}
	for i, w := range want {
		g := got.files[i]
		if g.Field != w.Field || g.Filename != w.Filename || g.Format != w.Format || g.Signed != w.Signed || g.Parent {
			t.Errorf("Files[%d] = %+v, want %+v", i, g, w)
		}
		if g.Size != len(got.form[g.Field]) {
			t.Errorf("Files[%d].Size %d, file %d bytes", i, g.Size, len(got.form[g.Field]))
		}
	}
}

func TestWholeBody(t *testing.T) {
	for _, name := range []string{"small.jpg", "small.png", "small.webp", "sample.avif"} {
		var got received
		mw := newMiddleware(t, middleware.Config{})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("PUT", "/photo", bytes.NewReader(fixture(t, name)))
		req.Header.Set("Content-Type", "image/whatever") // the bytes decide the format
		mw(handler(t, &got)).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: status %d: %s", name, rec.Code, rec.Body)
		}
		trusted(t, name, got.body)
		if len(got.files) != 1 || !got.files[0].Signed {
			t.Errorf("%s: Files %+v", name, got.files)
		}
	}
}

// Re-uploading a signed image keeps its credentials as the parent.
func TestResign(t *testing.T) {
	signed, err := c2paseal.SignBytes(fixture(t, "small.jpg"), testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	var got received
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", bytes.NewReader(signed))
	req.Header.Set("Content-Type", "image/jpeg")
	newMiddleware(t, middleware.Config{})(handler(t, &got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || len(got.files) != 1 || !got.files[0].Parent {
		t.Fatalf("status %d, Files %+v", rec.Code, got.files)
	}
	trusted(t, "resigned", got.body)
}

func TestPassThrough(t *testing.T) {
	jpg := fixture(t, "small.jpg")
	for _, tc := range []struct{ name, ct string }{
		{"json", "application/json"},
		{"no content type", ""},
		{"bad content type", "image/;;"},
	} {
		var got received
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", bytes.NewReader(jpg))
		if tc.ct != "" {
			req.Header.Set("Content-Type", tc.ct)
		}
		newMiddleware(t, middleware.Config{})(handler(t, &got)).ServeHTTP(rec, req)
		if !got.called || !bytes.Equal(got.body, jpg) || got.files != nil {
			t.Errorf("%s: not passed through unchanged (called %v, files %+v)", tc.name, got.called, got.files)
		}
	}
	// Fields limits which parts are signed.
	body, ct := multipartBody(t, []part{
		{field: "avatar", filename: "a.jpg", contentType: "image/jpeg", data: jpg},
		{field: "other", filename: "b.jpg", contentType: "image/jpeg", data: jpg},
	})
	var got received
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", ct)
	newMiddleware(t, middleware.Config{Fields: []string{"avatar"}})(handler(t, &got)).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	trusted(t, "avatar", got.form["avatar"])
	if !bytes.Equal(got.form["other"], jpg) {
		t.Error("field outside Fields was changed")
	}
}

type failingSigner struct{ crypto.Signer }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("kms unavailable")
}

func TestRejections(t *testing.T) {
	jpg := fixture(t, "small.jpg")
	corrupt := append([]byte{}, jpg[:200]...) // a JPEG cut short
	failing := testOptions(t)
	failing.Signer = failingSigner{failing.Signer}
	mp := func(field, filename string, data []byte) (io.Reader, string) {
		b, ct := multipartBody(t, []part{{field: field, filename: filename, contentType: "application/octet-stream", data: data}})
		return b, ct
	}
	for _, tc := range []struct {
		name   string
		cfg    middleware.Config
		body   func() (io.Reader, string)
		status int
	}{
		{"too large", middleware.Config{MaxBytes: 1000},
			func() (io.Reader, string) { return bytes.NewReader(jpg), "image/jpeg" }, http.StatusRequestEntityTooLarge},
		{"unsupported, rejected", middleware.Config{RejectUnsupported: true},
			func() (io.Reader, string) { return mp("f", "x.txt", []byte("hello")) }, http.StatusUnsupportedMediaType},
		{"unsupported body, rejected", middleware.Config{RejectUnsupported: true},
			func() (io.Reader, string) { return strings.NewReader("GIF89a..."), "image/gif" }, http.StatusUnsupportedMediaType},
		{"corrupt image", middleware.Config{},
			func() (io.Reader, string) { return mp("f", "x.jpg", corrupt) }, http.StatusUnprocessableEntity},
		{"signer fails", middleware.Config{Options: failing},
			func() (io.Reader, string) { return bytes.NewReader(jpg), "image/jpeg" }, http.StatusInternalServerError},
		{"prepare fails", middleware.Config{Prepare: func(*http.Request, *middleware.File, *sign.Options) error { return errors.New("no user") }},
			func() (io.Reader, string) { return bytes.NewReader(jpg), "image/jpeg" }, http.StatusBadRequest},
		{"no boundary", middleware.Config{},
			func() (io.Reader, string) { return strings.NewReader("x"), "multipart/form-data" }, http.StatusBadRequest},
		{"malformed multipart", middleware.Config{},
			func() (io.Reader, string) {
				return strings.NewReader("--b\r\nbroken"), "multipart/form-data; boundary=b"
			}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got received
			body, ct := tc.body()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/", body)
			req.Header.Set("Content-Type", ct)
			newMiddleware(t, tc.cfg)(handler(t, &got)).ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Errorf("status %d, want %d: %s", rec.Code, tc.status, rec.Body)
			}
			if got.called {
				t.Error("handler called for a rejected request")
			}
			if tc.status == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "kms") {
				t.Errorf("500 leaks the error: %q", rec.Body)
			}
		})
	}
}

func TestConfig(t *testing.T) {
	if _, err := middleware.Sign(middleware.Config{}); !errors.Is(err, sign.ErrNoSigner) {
		t.Errorf("no options: %v", err)
	}
	if _, err := middleware.Sign(middleware.Config{Options: &sign.Options{}}); !errors.Is(err, sign.ErrNoSigner) {
		t.Errorf("empty options: %v", err)
	}
}
