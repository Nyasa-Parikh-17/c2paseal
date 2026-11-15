package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/examples/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

func post(t *testing.T, url, filename string, data []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, _ := w.CreateFormFile("photo", filename)
	fw.Write(data)
	w.Close()
	resp, err := http.Post(url, w.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUpload(t *testing.T) {
	td := fixtures.Testdata(t)
	dir := t.TempDir()
	h, err := newServer(context.Background(),
		filepath.Join(td, "pki", "leaf-chain.pem"), "file:"+filepath.Join(td, "pki", "leaf.key"), dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	jpg, _ := os.ReadFile(filepath.Join(td, "unsigned", "small.jpg"))
	resp := post(t, srv.URL+"/upload", "../my holiday.jpg", jpg)
	defer resp.Body.Close()
	var got map[string]any
	json.NewDecoder(resp.Body).Decode(&got)
	if resp.StatusCode != 200 || got["saved"] != "my_holiday.jpg" || got["signed"] != true {
		t.Fatalf("status %d, answer %v", resp.StatusCode, got)
	}
	anchors, _ := c2paseal.LoadTrustAnchors(filepath.Join(td, "pki", "trust-anchors.pem"))
	res := c2paseal.VerifyFile(filepath.Join(dir, "my_holiday.jpg"), &c2paseal.VerifyOptions{TrustAnchors: anchors})
	if res.State() != verify.Trusted {
		t.Errorf("saved file: %s %v", res.State(), res.Statuses())
	}

	resp2 := post(t, srv.URL+"/upload", "notes.txt", []byte("hello"))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text upload: status %d", resp2.StatusCode)
	}
}
