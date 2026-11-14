//go:build !js

package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
	"github.com/Nyasa-Parikh-17/c2paseal/web"
)

// siteCase is a file the site test drops on the Verify tab, and what the
// page must show for it.
type siteCase struct {
	Name  string `json:"name"`
	File  string `json:"file"`
	Trust bool   `json:"trust"`

	state, title string   // the banner
	text         []string // in the banner's text
	manifests    int      // manifest cards in the provenance graph (0: no graph)
}

// shown is what the page showed, as testdata/site.html reads it.
type shown struct {
	Name           string `json:"name"`
	File           string `json:"file"`
	State          string `json:"state"`
	Title          string `json:"title"`
	Text           string `json:"text"`
	GraphNodes     int    `json:"graphNodes"`
	GraphManifests int    `json:"graphManifests"`
	RawJSON        bool   `json:"rawJSON"`
	Statuses       int    `json:"statuses"`
	VisibleText    string `json:"visibleText"`
	Download       string `json:"download"`
	DownloadName   string `json:"downloadName"`
}

var siteCases = []siteCase{
	{Name: "signed, untrusted", File: "signed/small.jpg", state: "untrusted", title: "Signer not on your trust list",
		text: []string{"Signed by C2paSeal Test Signer (certificate issued by C2paSeal TEST ONLY), unmodified since it was signed.", "no time-stamp"}, manifests: 1},
	{Name: "signed PNG, trusted", File: "signed/small.png", Trust: true, state: "valid", title: "Valid, trusted signer",
		text: []string{"Signed by C2paSeal Test Signer"}, manifests: 1},
	{Name: "time-stamped, trusted", File: "signed/titled-ts.jpg", Trust: true, state: "valid", title: "Valid, trusted signer",
		text: []string{"unmodified since 2026-10-17 06:25 UTC, the time in its time-stamp."}, manifests: 1},
	{Name: "tampered JPEG", File: "broken/data-flip.jpg", Trust: true, state: "invalid", title: "Changed since it was signed",
		text: []string{"no longer matches"}, manifests: 1},
	{Name: "tampered PNG", File: "broken/data-flip.png", Trust: true, state: "invalid", title: "Changed since it was signed", manifests: 1},
	{Name: "expired signer", File: "broken/expired.jpg", Trust: true, state: "invalid", title: "Content Credentials not valid", manifests: 1},
	{Name: "no credentials", File: "unsigned/small.png", state: "none", title: "No Content Credentials", text: []string{"not a sign of tampering"}},
	{Name: "edit history", File: "legacy/CACA.jpg", manifests: 2},
}

// TestSite runs the web app in headless Chrome as a person would: drop
// files, read the banner, sign the sample, sign the result again. With the
// WebAssembly build it then cuts the server off and checks that the app
// still loads and works from its service worker. Under `serve` (no .wasm)
// the same page must use the HTTP API. Runs with C2PASEAL_BROWSER_TEST=1.
func TestSite(t *testing.T) {
	if os.Getenv("C2PASEAL_BROWSER_TEST") != "1" {
		t.Skip("set C2PASEAL_BROWSER_TEST=1 to run the headless browser test")
	}
	chrome := findChrome()
	if chrome == "" {
		t.Fatal("C2PASEAL_BROWSER_TEST=1 but no Chrome found; set C2PASEAL_CHROME")
	}
	anchors, err := c2paseal.ParseTrustAnchors(readFile(t, "pki/trust-anchors.pem"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wasm", func(t *testing.T) {
		wasm := wasmFile(t)
		wasmExec := filepath.Join(goEnv(t, "GOROOT"), "lib", "wasm", "wasm_exec.js")
		static := http.FileServerFS(web.Site())
		app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/c2paseal.wasm":
				w.Header().Set("Content-Type", "application/wasm")
				http.ServeFile(w, r, wasm)
			case "/wasm_exec.js":
				http.ServeFile(w, r, wasmExec)
			default:
				static.ServeHTTP(w, r)
			}
		})
		rep := runSite(t, chrome, app, true)
		if rep.Mode != "wasm" || !strings.Contains(rep.Where, "Files are not uploaded") {
			t.Errorf("mode %q, where %q; want the WebAssembly engine", rep.Mode, rep.Where)
		}
		checkSite(t, rep, anchors)
		t.Run("offline", func(t *testing.T) {
			if !rep.Controlled {
				t.Fatal("the service worker never controlled the app")
			}
			if rep.Offline == nil {
				t.Fatal("no offline result")
			}
			if rep.Offline.Mode != "wasm" {
				t.Errorf("offline mode %q", rep.Offline.Mode)
			}
			if rep.servedOffline != 0 {
				t.Errorf("%d app requests reached the server while it was off; all should come from the service worker", rep.servedOffline)
			}
			checkShown(t, rep.Offline.Verify, siteCases[1])
			if rep.Offline.Sign.State != "untrusted" || rep.Offline.Sign.Download == "" {
				t.Errorf("signing offline: %+v", rep.Offline.Sign)
			}
		})
	})

	t.Run("serve", func(t *testing.T) {
		cfg, err := web.LoadTestPKI(filepath.Join(td, "pki"))
		if err != nil {
			t.Fatal(err)
		}
		rep := runSite(t, chrome, web.Handler(cfg), false)
		if rep.Mode != "server" || !strings.Contains(rep.Where, "c2paseal serve") {
			t.Errorf("mode %q, where %q; want the HTTP API engine", rep.Mode, rep.Where)
		}
		checkSite(t, rep, anchors)
	})
}

type siteReport struct {
	Error          string  `json:"error"`
	Mode           string  `json:"mode"`
	Where          string  `json:"where"`
	Verify         []shown `json:"verify"`
	Sign           []shown `json:"sign"`
	SignTabVisible bool    `json:"signTabVisible"`
	Controlled     bool    `json:"controlled"`
	Offline        *struct {
		Mode   string `json:"mode"`
		Verify shown  `json:"verify"`
		Sign   shown  `json:"sign"`
	} `json:"offline"`

	servedOffline int64 // app requests the server answered while "off"
}

// runSite serves app under /app/ (as GitHub Pages serves the site under
// /c2paseal/) next to the test page, and returns what the page reports.
func runSite(t *testing.T, chrome string, app http.Handler, offline bool) *siteReport {
	t.Helper()
	page, err := os.ReadFile(filepath.Join("testdata", "site.html"))
	if err != nil {
		t.Fatal(err)
	}
	cases, _ := json.Marshal(map[string]any{"verify": siteCases, "offline": siteCases[1]})
	var off atomic.Bool
	var servedOffline atomic.Int64
	got := make(chan siteReport, 1)
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if off.Load() {
			servedOffline.Add(1)
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		app.ServeHTTP(w, r)
	})))
	mux.HandleFunc("GET /__test/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.HandleFunc("GET /__test/cases.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(cases)
	})
	mux.Handle("GET /__test/f/", http.StripPrefix("/__test/f/", http.FileServer(http.Dir(td))))
	mux.HandleFunc("POST /__test/offline", func(w http.ResponseWriter, r *http.Request) { off.Store(true) })
	mux.HandleFunc("POST /__test/result", func(w http.ResponseWriter, r *http.Request) {
		var rep siteReport
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
	t.Cleanup(srv.Close)

	url := srv.URL + "/__test/"
	if offline {
		url += "?offline=1"
	}
	ctx, stderr := startChrome(t, chrome, url)
	var rep siteReport
	select {
	case rep = <-got:
	case <-ctx.Done():
		t.Fatalf("no result from the browser within the timeout; Chrome stderr:\n%s", stderr.String())
	}
	if rep.Error != "" {
		t.Fatalf("browser: %s", rep.Error)
	}
	rep.servedOffline = servedOffline.Load()
	return &rep
}

// spin matches words the spec's wording avoids: the app says what was
// checked ("signed by X, unmodified since …"), never that a picture is
// real.
var spin = regexp.MustCompile(`(?i)\b(real|true|genuine|authentic|fake)\b`)

func checkSite(t *testing.T, rep *siteReport, anchors []*x509.Certificate) {
	if len(rep.Verify) != len(siteCases) {
		t.Fatalf("page returned %d verify results for %d cases", len(rep.Verify), len(siteCases))
	}
	for i, c := range siteCases {
		t.Run(c.Name, func(t *testing.T) { checkShown(t, rep.Verify[i], c) })
	}
	t.Run("sign the sample", func(t *testing.T) {
		if !rep.SignTabVisible {
			t.Error("the Sign tab did not show")
		}
		if len(rep.Sign) != 2 {
			t.Fatalf("got %d sign results, want 2 (sample, again)", len(rep.Sign))
		}
		for i, want := range []struct {
			name      string
			manifests int
		}{{"sample.signed.jpg", 1}, {"sample.signed.signed.jpg", 2}} {
			s := rep.Sign[i]
			if s.State != "untrusted" || s.DownloadName != want.name || s.GraphManifests != want.manifests || !s.RawJSON {
				t.Errorf("sign %d: state %q, download %q, %d manifests in the graph, raw JSON %v; want untrusted, %s, %d, true",
					i, s.State, s.DownloadName, s.GraphManifests, s.RawJSON, want.name, want.manifests)
			}
			if !strings.Contains(s.Text, "Signed by C2paSeal Test Signer") {
				t.Errorf("sign %d: banner text %q", i, s.Text)
			}
			// The downloaded file is what the page says: signed with the
			// demo certificate, Trusted under the demo root.
			b, err := base64.StdEncoding.DecodeString(s.Download)
			if err != nil || len(b) == 0 {
				t.Fatalf("sign %d: no download (%v)", i, err)
			}
			if st := c2paseal.VerifyBytes(b, &c2paseal.VerifyOptions{TrustAnchors: anchors}).State(); st != verify.Trusted {
				t.Errorf("sign %d: downloaded file verifies %s here, want Trusted", i, st)
			}
			if m := spin.FindString(s.VisibleText); m != "" {
				t.Errorf("sign %d: page says %q", i, m)
			}
		}
	})
}

func checkShown(t *testing.T, s shown, c siteCase) {
	t.Helper()
	if s.Name != c.Name || s.File != filepath.Base(c.File) {
		t.Fatalf("result for %q (%s), want %q (%s)", s.Name, s.File, c.Name, c.File)
	}
	if c.state != "" && (s.State != c.state || s.Title != c.title) {
		t.Errorf("banner %q %q, want %q %q (text %q)", s.State, s.Title, c.state, c.title, s.Text)
	}
	for _, want := range c.text {
		if !strings.Contains(s.Text, want) {
			t.Errorf("banner text %q does not contain %q", s.Text, want)
		}
	}
	if s.GraphManifests < c.manifests || (c.manifests == 0 && s.GraphNodes != 0) {
		t.Errorf("provenance graph: %d manifest cards (%d nodes), want %d", s.GraphManifests, s.GraphNodes, c.manifests)
	}
	if (c.manifests > 0) != s.RawJSON {
		t.Errorf("raw manifest view shown: %v", s.RawJSON)
	}
	if s.Statuses == 0 {
		t.Error("no validation statuses listed")
	}
	if m := spin.FindString(s.VisibleText); m != "" {
		t.Errorf("page says %q: %q", m, s.VisibleText)
	}
}
