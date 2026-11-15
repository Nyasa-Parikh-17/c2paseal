package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/jpeg"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	c2pajpeg "github.com/Nyasa-Parikh-17/c2paseal/container/jpeg"
	"github.com/Nyasa-Parikh-17/c2paseal/sign/signtest"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark"
	"github.com/Nyasa-Parikh-17/c2paseal/watermark/wmfile"
	"golang.org/x/image/draw"
)

const apiKey = "sk_test_store_0123456789abcdefghijklm"

func keysFor(key string) map[[sha256.Size]byte]string {
	return map[[sha256.Size]byte]string{sha256.Sum256([]byte(key)): "test"}
}

func newStore(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var audit bytes.Buffer
	s := &server{store: &fileStore{dir: t.TempDir()}, keys: keysFor(apiKey), maxBytes: 1 << 20,
		audit: slog.New(slog.NewJSONHandler(&audit, nil)), version: "test"}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return srv, &audit
}

func photo(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "watermark", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signOpts(t *testing.T) *c2paseal.SignOptions {
	t.Helper()
	td := signtest.TestdataDir(t)
	chain, key, err := c2paseal.LoadSigner(filepath.Join(td, "pki", "leaf-chain.pem"), filepath.Join(td, "pki", "leaf.key"))
	if err != nil {
		t.Fatal(err)
	}
	return &c2paseal.SignOptions{Chain: chain, Signer: key}
}

func reencode(t *testing.T, b []byte, scale float64, q int) []byte {
	t.Helper()
	img, _, err := wmfile.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if scale != 1 {
		r := img.Bounds()
		out := image.NewNRGBA(image.Rect(0, 0, int(float64(r.Dx())*scale), int(float64(r.Dy())*scale)))
		draw.CatmullRom.Scale(out, out.Bounds(), img, r, draw.Src, nil)
		img = out
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestRecovery is the phase's check: sign (watermark plus soft binding),
// strip the manifest, re-encode, recover, verify. The recovered manifest's
// signature validates and is Trusted under the TEST ONLY root; the copy is
// reported as changed (its hard binding cannot match), and the watermark
// it carries is the one the manifest records.
func TestRecovery(t *testing.T) {
	srv, audit := newStore(t)
	anchors, err := c2paseal.LoadTrustAnchors(filepath.Join(signtest.TestdataDir(t), "pki", "trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"IMG_0003.jpg", "sample1.png"} {
		t.Run(name, func(t *testing.T) {
			res, err := watermarkAndSign(photo(t, name), signOpts(t))
			if err != nil {
				t.Fatal(err)
			}
			signedPath := filepath.Join(t.TempDir(), "signed-"+name)
			os.WriteFile(signedPath, res.file, 0o644)
			signtest.CheckFile(t, signedPath) // c2patool accepts the watermarked, signed file
			if err := upload(ctx, srv.Client(), srv.URL, apiKey, res.id, res.store); err != nil {
				t.Fatal(err)
			}
			copies := map[string][]byte{
				"re-encoded (JPEG 80)":     reencode(t, res.file, 1, 80),
				"resized 75 %, JPEG 85":    reencode(t, res.file, 0.75, 85),
				"manifest stripped (only)": stripOnly(t, res.file),
			}
			for what, copyBytes := range copies {
				if _, err := c2paseal.ReadBytes(copyBytes); err == nil {
					t.Fatalf("%s: the copy still has a manifest", what)
				}
				rc := recoverCredentials(ctx, srv.Client(), copyBytes, srv.URL, anchors)
				if !rc.Recovered || !rc.SignatureValid || !rc.Trusted || !rc.ContentChanged || rc.WatermarkID != res.id.String() || rc.ActiveManifest != res.manifest {
					t.Errorf("%s: %+v", what, rc)
					continue
				}
				if !strings.Contains(rc.describe(), "signed by C2paSeal Test Signer") {
					t.Errorf("%s: %s", what, rc.describe())
				}
				t.Logf("%s: recovered %s (watermark confidence %.2f)", what, rc.WatermarkID, rc.Confidence)
			}
			// Without trust anchors the signature still validates; the
			// signer is reported as untrusted.
			rc := recoverCredentials(ctx, srv.Client(), copies["re-encoded (JPEG 80)"], srv.URL, nil)
			if !rc.Recovered || rc.Trusted {
				t.Errorf("no anchors: %+v", rc)
			}
		})
	}
	if !strings.Contains(audit.String(), `"api_key":"test"`) || strings.Contains(audit.String(), apiKey) {
		t.Errorf("audit log: %s", audit.String())
	}
}

// stripOnly removes the manifest store without touching the image data.
func stripOnly(t *testing.T, b []byte) []byte {
	t.Helper()
	if c2paseal.DetectFormat(b) == c2paseal.FormatJPEG {
		s, err := c2pajpeg.Strip(b)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// PNG: drop the caBX chunk.
	out := append([]byte(nil), b[:8]...)
	for i := 8; i+12 <= len(b); {
		n := int(uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3]))
		if string(b[i+4:i+8]) != "caBX" {
			out = append(out, b[i:i+12+n]...)
		}
		i += 12 + n
	}
	return out
}

func TestRecoveryFailures(t *testing.T) {
	srv, _ := newStore(t)
	ctx := context.Background()
	// No watermark.
	if rc := recoverCredentials(ctx, srv.Client(), photo(t, "P1000827.jpg"), srv.URL, nil); rc.Recovered || !strings.Contains(rc.Problem, "no watermark") {
		t.Errorf("unmarked: %+v", rc)
	}
	// Watermarked and signed, never uploaded.
	res, err := watermarkAndSign(photo(t, "IMG_0003.jpg"), signOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if rc := recoverCredentials(ctx, srv.Client(), res.file, srv.URL, nil); rc.Recovered || !strings.Contains(rc.Problem, errNotFound.Error()) {
		t.Errorf("not uploaded: %+v", rc)
	}
	// Not an image; store unreachable.
	if rc := recoverCredentials(ctx, srv.Client(), []byte("hello"), srv.URL, nil); rc.Recovered || rc.Problem == "" {
		t.Errorf("garbage: %+v", rc)
	}
	if rc := recoverCredentials(ctx, srv.Client(), res.file, "http://127.0.0.1:1", nil); rc.Recovered || !strings.Contains(rc.Problem, "manifest store:") {
		t.Errorf("store down: %+v", rc)
	}
}

func TestStoreAPI(t *testing.T) {
	srv, _ := newStore(t)
	res, err := watermarkAndSign(photo(t, "IMG_0003.jpg"), signOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	put := func(id, key string, body []byte) (int, string) {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/manifests/"+id, bytes.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	other, _ := watermark.NewID()
	for _, tc := range []struct {
		name, id, key string
		body          []byte
		code          int
		msg           string
	}{
		{"no key", res.id.String(), "", res.store, 401, "API key"},
		{"wrong key", res.id.String(), "sk_nope", res.store, 401, "API key"},
		{"bad id", "xyz", apiKey, res.store, 400, "16 hex digits"},
		{"not a store", res.id.String(), apiKey, []byte("hello"), 422, "not a manifest store"},
		{"another ID's store", other.String(), apiKey, res.store, 422, "does not carry"},
		{"too large", res.id.String(), apiKey, make([]byte, 2<<20), 413, "body over"},
		{"created", res.id.String(), apiKey, res.store, 201, `"replaced":false`},
		{"replaced", res.id.String(), apiKey, res.store, 200, `"replaced":true`},
	} {
		if code, body := put(tc.id, tc.key, tc.body); code != tc.code || !strings.Contains(body, tc.msg) {
			t.Errorf("%s: %d %s", tc.name, code, body)
		}
	}
	// A store without our soft binding is refused.
	plain, err := c2paseal.SignAsset(photo(t, "IMG_0003.jpg"), signOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if code, body := put(res.id.String(), apiKey, plain.Store); code != 422 || !strings.Contains(body, "soft binding") {
		t.Errorf("no soft binding: %d %s", code, body)
	}
	for path, want := range map[string]int{"/v1/manifests/" + res.id.String(): 200, "/v1/manifests/" + other.String(): 404, "/v1/manifests/nope": 400, "/healthz": 200} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s: %d, want %d", path, resp.StatusCode, want)
		}
		if strings.HasPrefix(path, "/v1/") && resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("GET %s: no CORS header", path)
		}
		if want == 200 && strings.HasPrefix(path, "/v1/") && (!bytes.Equal(body, res.store) || resp.Header.Get("Content-Type") != "application/c2pa") {
			t.Errorf("GET %s: wrong body or type", path)
		}
	}
	if keys, err := parseKeys(strings.NewReader("# c\nci " + hex.EncodeToString(make([]byte, 32)) + "\n")); err != nil || len(keys) != 1 {
		t.Errorf("parseKeys: %v %v", keys, err)
	}
	for _, bad := range []string{"", "onlyname\n", "a nothex\n"} {
		if _, err := parseKeys(strings.NewReader(bad)); err == nil {
			t.Errorf("parseKeys(%q) succeeded", bad)
		}
	}
}

// TestCLI runs the real commands: serve, sign with upload, recover of a
// re-encoded copy, and the error paths.
func TestCLI(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keys.txt")
	h := sha256.Sum256([]byte(apiKey))
	os.WriteFile(keyFile, []byte("cli "+hex.EncodeToString(h[:])+"\n"), 0o600)
	storeDir := filepath.Join(dir, "stores")
	os.Mkdir(storeDir, 0o755)
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	done := make(chan int, 1)
	var errb bytes.Buffer
	go func() {
		done <- run(ctx, []string{"serve", "--addr", "127.0.0.1:0", "--dir", storeDir, "--api-keys", keyFile, "--audit-log", filepath.Join(dir, "audit.jsonl")}, pw, &errb)
		pw.Close()
	}()
	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil {
		t.Fatalf("serve: %v %s", err, errb.String())
	}
	go io.Copy(io.Discard, pr)
	url := strings.TrimSpace(strings.TrimPrefix(line, "sealstore listening on "))

	td := signtest.TestdataDir(t)
	in := filepath.Join("..", "..", "watermark", "testdata", "IMG_0003.jpg")
	out := filepath.Join(dir, "signed.jpg")
	var stdout bytes.Buffer
	if code := run(ctx, []string{"sign", "--json", "--cert", filepath.Join(td, "pki", "leaf-chain.pem"), "--key", filepath.Join(td, "pki", "leaf.key"),
		"--in", in, "--out", out, "--store", url, "--api-key", apiKey}, &stdout, &errb); code != 0 {
		t.Fatalf("sign: %d %s", code, errb.String())
	}
	var signed struct {
		ID       string `json:"watermark_id"`
		Uploaded bool   `json:"uploaded"`
	}
	if json.Unmarshal(stdout.Bytes(), &signed) != nil || !signed.Uploaded || len(signed.ID) != 16 {
		t.Fatalf("sign output: %s", stdout.String())
	}
	b, _ := os.ReadFile(out)
	copyPath := filepath.Join(dir, "copy.jpg")
	os.WriteFile(copyPath, reencode(t, b, 1, 75), 0o644)
	stdout.Reset()
	if code := run(ctx, []string{"recover", copyPath, "--store", url, "--trust", filepath.Join(td, "pki", "trust-anchors.pem")}, &stdout, &errb); code != 0 ||
		!strings.Contains(stdout.String(), "recovered: manifest") || !strings.Contains(stdout.String(), "the signer is on your trust list") || !strings.Contains(stdout.String(), signed.ID) {
		t.Errorf("recover: %d\n%s%s", code, stdout.String(), errb.String())
	}
	stdout.Reset()
	if code := run(ctx, []string{"recover", "--json", "--store", url, in}, &stdout, &errb); code != 1 || !strings.Contains(stdout.String(), `"recovered": false`) {
		t.Errorf("recover unmarked: %d %s", code, stdout.String())
	}
	for _, args := range [][]string{{}, {"nope"}, {"serve"}, {"sign"}, {"recover"}, {"serve", "--dir", filepath.Join(dir, "missing"), "--api-keys", keyFile},
		{"sign", "--cert", "c", "--key", "k", "--in", "i", "--out", "o", "--store", url}} {
		if code := run(ctx, args, io.Discard, io.Discard); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := run(ctx, []string{"version"}, io.Discard, io.Discard); code != 0 {
		t.Error("version")
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("serve exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}
