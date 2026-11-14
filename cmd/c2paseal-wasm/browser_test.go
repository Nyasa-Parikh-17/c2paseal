//go:build !js

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// WasmBudget is the most the gzipped c2paseal.wasm may weigh (gzip -9).
// The standard Go build was 3.70 MB at Phase 22. If it no longer fits, look
// at what grew before raising the budget; TinyGo is the fallback (see
// PROGRESS.md, Phase 22).
const WasmBudget = 4 << 20

var (
	wasmOnce sync.Once
	wasmPath string
	wasmErr  error
)

// wasmFile returns the WebAssembly build: $C2PASEAL_WASM if set (CI builds
// it once with the release flags), else a fresh build with those flags.
func wasmFile(t *testing.T) string {
	t.Helper()
	wasmOnce.Do(func() {
		if p := os.Getenv("C2PASEAL_WASM"); p != "" {
			wasmPath = p
			return
		}
		dir, err := os.MkdirTemp("", "c2paseal-wasm-")
		if err != nil {
			wasmErr = err
			return
		}
		wasmPath = filepath.Join(dir, "c2paseal.wasm")
		cmd := exec.Command(goTool(), "build", "-trimpath", "-ldflags=-s -w", "-o", wasmPath, ".")
		cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			wasmErr = &buildError{err, out}
		}
	})
	if wasmErr != nil {
		t.Fatal(wasmErr)
	}
	return wasmPath
}

type buildError struct {
	err error
	out []byte
}

func (e *buildError) Error() string { return "build wasm: " + e.err.Error() + "\n" + string(e.out) }

// goTool is the go command on PATH, which `go test` runs under.
func goTool() string { return "go" }

func goEnv(t *testing.T, key string) string {
	t.Helper()
	out, err := exec.Command(goTool(), "env", key).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// TestWasmSize enforces WasmBudget.
func TestWasmSize(t *testing.T) {
	b, err := os.ReadFile(wasmFile(t))
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	w, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	w.Write(b)
	w.Close()
	t.Logf("c2paseal.wasm: %d bytes, %d gzipped (budget %d, %.0f%% used)", len(b), gz.Len(), WasmBudget, 100*float64(gz.Len())/WasmBudget)
	if gz.Len() > WasmBudget {
		t.Errorf("gzipped c2paseal.wasm is %d bytes, over the %d-byte budget", gz.Len(), WasmBudget)
	}
}

// browserCase is one call the test page makes; see testdata/browser.html.
type browserCase struct {
	Name     string            `json:"name"`
	Op       string            `json:"op"`
	File     string            `json:"file,omitempty"`
	NotBytes bool              `json:"notBytes,omitempty"`
	Text     map[string]string `json:"text,omitempty"`  // option → fixture path, passed as a string
	Bytes    map[string]string `json:"bytes,omitempty"` // option → fixture path, passed as a Uint8Array
	Plain    map[string]any    `json:"plain,omitempty"` // options passed as they are
	Reverify *browserCase      `json:"reverify,omitempty"`

	// For the Go side only.
	check func(t *testing.T, r browserResult)
}

type browserResult struct {
	Name       string `json:"name"`
	Output     string `json:"output"`
	Reverified string `json:"reverified"`
}

// TestBrowser runs verify and sign on JPEG and PNG fixtures in headless
// Chrome and checks that the browser gives the same results as this
// process. It runs when C2PASEAL_BROWSER_TEST=1 (as in CI), with Chrome
// from $C2PASEAL_CHROME or a usual install location.
func TestBrowser(t *testing.T) {
	if os.Getenv("C2PASEAL_BROWSER_TEST") != "1" {
		t.Skip("set C2PASEAL_BROWSER_TEST=1 to run the headless browser test")
	}
	chrome := findChrome()
	if chrome == "" {
		t.Fatal("C2PASEAL_BROWSER_TEST=1 but no Chrome found; set C2PASEAL_CHROME")
	}
	wasm := wasmFile(t)
	wasmExec := filepath.Join(goEnv(t, "GOROOT"), "lib", "wasm", "wasm_exec.js")
	page, err := os.ReadFile(filepath.Join("testdata", "browser.html"))
	if err != nil {
		t.Fatal(err)
	}

	anchorsPEM := readFile(t, "pki/trust-anchors.pem")
	anchors, err := c2paseal.ParseTrustAnchors(anchorsPEM)
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]string{"trustAnchors": "f/pki/trust-anchors.pem"}
	signer := map[string]string{"cert": "f/pki/leaf-chain.pem", "key": "f/pki/leaf.key"}

	// sameAsHost: the browser's verify() output equals this process's for
	// the same file and options, byte for byte.
	sameAsHost := func(file string, o verifyOptions, want verify.State) func(*testing.T, browserResult) {
		return func(t *testing.T, r browserResult) {
			host := string(verifyJSON(readFile(t, file), o))
			if r.Output != host {
				t.Errorf("browser verify() differs from the host's:\nbrowser %.300s\n   host %.300s", r.Output, host)
			}
			if s := stateOf(t, r.Output); s != want {
				t.Errorf("validation_state %s, want %s", s, want)
			}
		}
	}
	// signed: sign() gave a file of the format, which this process and the
	// browser both verify as Trusted with the same JSON.
	signed := func(format string, manifests int) func(*testing.T, browserResult) {
		return func(t *testing.T, r browserResult) {
			var s signResult
			if err := json.Unmarshal([]byte(r.Output), &s); err != nil || s.Data == nil {
				t.Fatalf("sign() = %.300s", r.Output)
			}
			if s.Format != format || s.Manifests != manifests {
				t.Errorf("sign() format %s, %d manifests; want %s, %d", s.Format, s.Manifests, format, manifests)
			}
			host := string(verifyJSON(s.Data, verifyOptions{TrustAnchors: string(anchorsPEM)}))
			if r.Reverified != host {
				t.Errorf("browser verify() of the signed file differs from the host's:\nbrowser %.300s\n   host %.300s", r.Reverified, host)
			}
			if st := c2paseal.VerifyBytes(s.Data, &c2paseal.VerifyOptions{TrustAnchors: anchors}).State(); st != verify.Trusted {
				t.Errorf("signed file verifies %s here, want Trusted", st)
			}
		}
	}
	isError := func(want string) func(*testing.T, browserResult) {
		return func(t *testing.T, r browserResult) {
			if e := errorOf(t, []byte(r.Output)); !strings.Contains(e, want) {
				t.Errorf("error %q, want it to contain %q", e, want)
			}
		}
	}
	a := verifyOptions{TrustAnchors: string(anchorsPEM)}
	cases := []browserCase{
		{Name: "verify signed JPEG", Op: "verify", File: "signed/small.jpg", check: sameAsHost("signed/small.jpg", verifyOptions{}, verify.Valid)},
		{Name: "verify signed JPEG, trusted", Op: "verify", File: "signed/small.jpg", Text: trusted, check: sameAsHost("signed/small.jpg", a, verify.Trusted)},
		{Name: "verify signed PNG, trusted", Op: "verify", File: "signed/small.png", Text: trusted, check: sameAsHost("signed/small.png", a, verify.Trusted)},
		{Name: "verify time-stamped JPEG, trusted", Op: "verify", File: "signed/titled-ts.jpg", Text: trusted, check: sameAsHost("signed/titled-ts.jpg", a, verify.Trusted)},
		{Name: "verify tampered JPEG", Op: "verify", File: "broken/data-flip.jpg", Text: trusted, check: sameAsHost("broken/data-flip.jpg", a, verify.Invalid)},
		{Name: "verify tampered PNG", Op: "verify", File: "broken/data-flip.png", Text: trusted, check: sameAsHost("broken/data-flip.png", a, verify.Invalid)},
		{Name: "verify unsigned PNG", Op: "verify", File: "unsigned/small.png", check: sameAsHost("unsigned/small.png", verifyOptions{}, verify.Invalid)},
		{Name: "sign JPEG", Op: "sign", File: "unsigned/small.jpg", Text: signer, Plain: map[string]any{"title": "browser test"}, Reverify: &browserCase{Text: trusted}, check: signed("jpeg", 1)},
		{Name: "sign PNG", Op: "sign", File: "unsigned/large.png", Text: signer, Reverify: &browserCase{Text: trusted}, check: signed("png", 1)},
		{Name: "re-sign signed JPEG", Op: "sign", File: "signed/small.jpg", Text: signer, Reverify: &browserCase{Text: trusted}, check: signed("jpeg", 2)},
		{Name: "bad trust anchors", Op: "verify", File: "signed/small.jpg", Plain: map[string]any{"trustAnchors": "not PEM"}, check: isError("trustAnchors: ")},
		{Name: "sign without key", Op: "sign", File: "unsigned/small.jpg", Text: map[string]string{"cert": "f/pki/leaf-chain.pem"}, check: isError("cert and key are required")},
		{Name: "verify a string", Op: "verify", NotBytes: true, check: isError("bytes must be a Uint8Array")},
	}
	for i := range cases {
		if cases[i].File != "" {
			cases[i].File = "f/" + cases[i].File
		}
	}
	casesJSON, _ := json.Marshal(cases)

	type report struct {
		Error     string          `json:"error"`
		UserAgent string          `json:"userAgent"`
		Version   string          `json:"version"`
		Results   []browserResult `json:"results"`
	}
	got := make(chan report, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.HandleFunc("GET /wasm_exec.js", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, wasmExec) })
	mux.HandleFunc("GET /c2paseal.wasm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		http.ServeFile(w, r, wasm)
	})
	mux.HandleFunc("GET /cases.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(casesJSON)
	})
	mux.Handle("GET /f/", http.StripPrefix("/f/", http.FileServer(http.Dir(td))))
	mux.HandleFunc("POST /result", func(w http.ResponseWriter, r *http.Request) {
		var rep report
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &rep); err != nil {
			rep.Error = "bad report: " + err.Error()
		}
		select {
		case got <- rep:
		default:
		}
	})
	mux.HandleFunc("GET /favicon.ico", http.NotFound)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	profile, err := os.MkdirTemp("", "c2paseal-chrome-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(profile) // best effort: Chrome's helpers may still hold files on Windows
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome,
		"--headless=new", "--no-sandbox", "--disable-gpu", "--disable-extensions",
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--user-data-dir="+profile, srv.URL+"/")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	var rep report
	select {
	case rep = <-got:
	case <-ctx.Done():
		t.Fatalf("no result from the browser within the timeout; Chrome stderr:\n%s", stderr.String())
	}
	if rep.Error != "" {
		t.Fatalf("browser: %s", rep.Error)
	}
	t.Logf("browser: %s; c2paseal.version() = %s", rep.UserAgent, rep.Version)
	if len(rep.Results) != len(cases) {
		t.Fatalf("browser returned %d results for %d cases", len(rep.Results), len(cases))
	}
	for i, c := range cases {
		r := rep.Results[i]
		t.Run(c.Name, func(t *testing.T) {
			if r.Name != c.Name {
				t.Fatalf("result %d is %q", i, r.Name)
			}
			c.check(t, r)
		})
	}
}

func stateOf(t *testing.T, out string) verify.State {
	t.Helper()
	var r verifyResult
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not verify() JSON: %.200s", out)
	}
	return r.State
}

// findChrome returns $C2PASEAL_CHROME or the first Chrome or Chromium found.
func findChrome() string {
	if p := os.Getenv("C2PASEAL_CHROME"); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	var paths []string
	switch runtime.GOOS {
	case "windows":
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if d := os.Getenv(env); d != "" {
				paths = append(paths, filepath.Join(d, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
	case "darwin":
		paths = append(paths, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
