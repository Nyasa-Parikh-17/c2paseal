package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func server(t *testing.T) *httptest.Server {
	t.Helper()
	dir, err := fixtures.Dir()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadTestPKI(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(cfg))
	t.Cleanup(srv.Close)
	return srv
}

// post uploads a file like the page does and decodes the JSON answer.
func post(t *testing.T, srv *httptest.Server, path, name string, data []byte, trust bool) (int, Analysis, map[string]string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(data)
	if trust {
		mw.WriteField("trust", "1")
	}
	mw.Close()
	resp, err := http.Post(srv.URL+path, mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var a Analysis
	var e map[string]string
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, raw)
		}
	} else {
		json.Unmarshal(raw, &e)
	}
	return resp.StatusCode, a, e
}

func codesOf(a Analysis, kind string) []string {
	var out []string
	for _, s := range a.Statuses {
		if s.Kind == kind {
			out = append(out, s.Code)
		}
	}
	return out
}

// Done-when, at the HTTP level: drop → verify → sign → re-verify works for
// a JPEG and a PNG.
func TestDropVerifySignReverify(t *testing.T) {
	srv := server(t)
	dir, _ := fixtures.Dir()
	for _, name := range []string{"small.jpg", "small.png"} {
		in, err := os.ReadFile(filepath.Join(dir, "unsigned", name))
		if err != nil {
			t.Fatal(err)
		}
		// Drop: an unsigned file has no manifest.
		code, a, _ := post(t, srv, "/api/verify", name, in, false)
		if code != http.StatusOK || a.State != verify.Invalid || !slices.Equal(codesOf(a, "failure"), []string{verify.ClaimMissing}) || a.ManifestStore != nil {
			t.Errorf("%s verify: %d, state %s, failures %q", name, code, a.State, codesOf(a, "failure"))
		}

		// Sign, untrusted then trusted.
		code, s, _ := post(t, srv, "/api/sign", name, in, false)
		if code != http.StatusOK || s.State != verify.Valid || !slices.Equal(codesOf(s, "failure"), []string{verify.SigningCredentialUntrusted}) {
			t.Errorf("%s sign: %d, state %s, failures %q", name, code, s.State, codesOf(s, "failure"))
		}
		if s.Signed == nil || !strings.Contains(s.Signed.Name, ".signed.") || s.ManifestStore == nil {
			t.Fatalf("%s sign: no signed file or manifest in the answer", name)
		}
		code, st, _ := post(t, srv, "/api/sign", name, in, true)
		if code != http.StatusOK || st.State != verify.Trusted || len(codesOf(st, "failure")) != 0 || !st.Trusted {
			t.Errorf("%s sign (trusted): %d, state %s, failures %q", name, code, st.State, codesOf(st, "failure"))
		}

		// The downloaded bytes are a real signed file: the library agrees,
		// and dropping them back in gives the same result.
		if got := c2paseal.VerifyBytes(s.Signed.Data, nil).State(); got != verify.Valid {
			t.Errorf("%s: downloaded file state %s", name, got)
		}
		code, again, _ := post(t, srv, "/api/verify", s.Signed.Name, s.Signed.Data, true)
		if code != http.StatusOK || again.State != verify.Trusted {
			t.Errorf("%s: re-dropped signed file: %d, state %s", name, code, again.State)
		}
		var store struct {
			Active string `json:"active_manifest"`
		}
		if err := json.Unmarshal(again.ManifestStore, &store); err != nil || !strings.HasPrefix(store.Active, "urn:c2pa:") {
			t.Errorf("%s: manifest store JSON: %v %q", name, err, store.Active)
		}
	}
}

func TestPageAndErrors(t *testing.T) {
	srv := server(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(page, []byte("TEST ONLY")) || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("page: %d %s, TEST ONLY label present: %v", resp.StatusCode, resp.Header.Get("Content-Type"), bytes.Contains(page, []byte("TEST ONLY")))
	}
	if resp, _ := http.Get(srv.URL + "/nope"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}

	// Garbage is analysed, not an error: Verify turns it into a status.
	code, a, _ := post(t, srv, "/api/verify", "x.txt", []byte("not an image"), false)
	if code != http.StatusOK || a.State != verify.Invalid || len(a.Statuses) == 0 || a.ReadError == "" {
		t.Errorf("garbage verify: %d, %+v", code, a)
	}
	// Signing garbage is refused with a message.
	code, _, e := post(t, srv, "/api/sign", "x.txt", []byte("not an image"), false)
	if code != http.StatusUnprocessableEntity || e["error"] == "" {
		t.Errorf("garbage sign: %d %v", code, e)
	}
	// No file field.
	resp, err = http.Post(srv.URL+"/api/verify", "multipart/form-data; boundary=x", strings.NewReader("--x--\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no file: %d", resp.StatusCode)
	}
	// No signer configured.
	bare := httptest.NewServer(Handler(&Config{}))
	defer bare.Close()
	if code, _, _ := post(t, bare, "/api/sign", "a.jpg", []byte{0xFF, 0xD8}, false); code != http.StatusServiceUnavailable {
		t.Errorf("sign without key: %d", code)
	}
}
