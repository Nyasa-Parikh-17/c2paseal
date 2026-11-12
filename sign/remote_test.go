package sign

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/container/xmp"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// storeServer serves manifest stores by path, as a remote manifest host.
type storeServer struct {
	mu     sync.Mutex
	stores map[string][]byte
	*httptest.Server
}

func newStoreServer(t *testing.T) *storeServer {
	s := &storeServer{stores: map[string][]byte{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		b, ok := s.stores[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", verify.MediaType)
		w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *storeServer) put(path string, b []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stores[path] = b
	return s.URL + path
}

func unsignedFile(t *testing.T, name string) []byte {
	t.Helper()
	dir, _ := fixtures.Dir()
	b, err := os.ReadFile(filepath.Join(dir, "unsigned", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkExternal verifies a file whose store is passed separately.
func checkExternal(t *testing.T, name string, file, store []byte) {
	t.Helper()
	r := verify.File(file, &verify.Options{ManifestStore: store})
	if got := failures(r); !slices.Equal(got, []string{verify.SigningCredentialUntrusted}) || !has(r, verify.AssertionDataHashMatch) {
		t.Errorf("%s: failures %q, state %s\n%+v", name, got, r.State(), r.ActiveManifest)
	}
	tr := verify.File(file, &verify.Options{ManifestStore: store, TrustAnchors: anchors(t)})
	if tr.State() != verify.Trusted {
		t.Errorf("%s with test root trusted: state %s, failures %q", name, tr.State(), failures(tr))
	}
}

func remoteURLOf(t *testing.T, file []byte) string {
	t.Helper()
	url, ok, err := asset.RemoteURL(file)
	if err != nil || !ok {
		t.Fatalf("no remote URL in XMP (%v)", err)
	}
	return url
}

// TestSidecar: the store is left out of the file, the image bytes are not
// touched, and the store verifies against the whole file.
func TestSidecar(t *testing.T) {
	chain, key := testPKI(t)
	for _, name := range []string{"small.jpg", "small.png", "exif.jpg"} {
		in := unsignedFile(t, name)
		s, err := Asset(in, &Options{Chain: chain, Signer: key, Sidecar: true})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(s.File, in) {
			t.Errorf("%s: sidecar signing changed the file", name)
		}
		if _, _, err := asset.Extract(s.File); !errors.Is(err, asset.ErrNoManifest) {
			t.Errorf("%s: file has an embedded store (%v)", name, err)
		}
		checkExternal(t, name, s.File, s.Store)
		if r := verify.File(s.File, nil); r.State() != verify.Invalid || r.ActiveManifest[0].Code != verify.ClaimMissing {
			t.Errorf("%s without its sidecar: %+v", name, r.ActiveManifest)
		}
		// A changed pixel breaks the binding, which covers the whole file.
		bad := bytes.Clone(s.File)
		bad[len(bad)-3] ^= 1
		if r := verify.File(bad, &verify.Options{ManifestStore: s.Store}); !slices.Contains(failures(r), verify.AssertionDataHashMismatch) {
			t.Errorf("%s: tampered file still matches: %q", name, failures(r))
		}
	}
}

// TestRemoteOnly: the file carries only the XMP reference; the store is
// fetched when FetchRemote is on, and reported inaccessible otherwise.
func TestRemoteOnly(t *testing.T) {
	chain, key := testPKI(t)
	srv := newStoreServer(t)
	for _, name := range []string{"small.jpg", "small.png"} {
		url := srv.URL + "/" + name + ".c2pa"
		s, err := Asset(unsignedFile(t, name), &Options{Chain: chain, Signer: key, Sidecar: true, RemoteURL: url})
		if err != nil {
			t.Fatal(err)
		}
		if got := remoteURLOf(t, s.File); got != url {
			t.Errorf("%s: XMP references %q, want %q", name, got, url)
		}

		r := verify.File(s.File, nil)
		if len(r.ActiveManifest) != 1 || r.ActiveManifest[0].Code != verify.ManifestInaccessible || r.State() != verify.Invalid {
			t.Errorf("%s offline: %+v", name, r.ActiveManifest)
		}
		r = verify.File(s.File, &verify.Options{FetchRemote: true})
		if r.ActiveManifest[0].Code != verify.ManifestInaccessible || !strings.Contains(r.ActiveManifest[0].Explanation, "404") {
			t.Errorf("%s before upload: %+v", name, r.ActiveManifest)
		}

		srv.put("/"+name+".c2pa", s.Store)
		r = verify.File(s.File, &verify.Options{FetchRemote: true})
		if got := failures(r); !slices.Equal(got, []string{verify.SigningCredentialUntrusted}) || !has(r, verify.AssertionDataHashMatch) {
			t.Errorf("%s fetched: failures %q\n%+v", name, got, r.ActiveManifest)
		}
		// A sidecar given by the caller wins over the remote reference.
		checkExternal(t, name+" with store", s.File, s.Store)
	}
}

// TestRemoteAndEmbedded: the store is embedded and also referenced from
// XMP; the embedded one is used, and the XMP is inside the hash.
func TestRemoteAndEmbedded(t *testing.T) {
	chain, key := testPKI(t)
	for _, name := range []string{"small.jpg", "small.png"} {
		s, err := Asset(unsignedFile(t, name), &Options{Chain: chain, Signer: key, RemoteURL: "https://example.com/a.c2pa"})
		if err != nil {
			t.Fatal(err)
		}
		checkSigned(t, name, s.File)
		if remoteURLOf(t, s.File) != "https://example.com/a.c2pa" {
			t.Errorf("%s: wrong remote URL", name)
		}
		// Re-signing replaces the reference and keeps the history.
		s2, err := Asset(s.File, &Options{Chain: chain, Signer: key, RemoteURL: "https://example.com/b.c2pa"})
		if err != nil {
			t.Fatal(err)
		}
		checkChild(t, name, s.File, s2.File)
		if remoteURLOf(t, s2.File) != "https://example.com/b.c2pa" {
			t.Errorf("%s: reference not replaced", name)
		}
		// Changing the XMP breaks the binding.
		bad, err := asset.SetRemoteURL(s2.File, "https://example.com/c.c2pa")
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(failures(verify.File(bad, nil)), verify.AssertionDataHashMismatch) {
			t.Errorf("%s: edited XMP still matches", name)
		}
	}
}

// TestRemoteKeepsXMP: an existing XMP packet keeps its other properties.
func TestRemoteKeepsXMP(t *testing.T) {
	chain, key := testPKI(t)
	packet := []byte(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` +
		`<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Someone</dc:creator></rdf:Description>` +
		`</rdf:RDF></x:xmpmeta>`)
	for _, name := range []string{"small.jpg", "small.png"} {
		in, err := asset.SetXMP(unsignedFile(t, name), packet)
		if err != nil {
			t.Fatal(err)
		}
		s, err := Asset(in, &Options{Chain: chain, Signer: key, RemoteURL: "https://example.com/x.c2pa"})
		if err != nil {
			t.Fatal(err)
		}
		checkSigned(t, name, s.File)
		got, _, _ := asset.XMP(s.File)
		if !bytes.Contains(got, []byte("<dc:creator>Someone</dc:creator>")) {
			t.Errorf("%s: XMP lost its other properties: %s", name, got)
		}
		if v, ok, _ := xmp.Provenance(got); !ok || v != "https://example.com/x.c2pa" {
			t.Errorf("%s: provenance %q", name, v)
		}
	}
}

func TestRemoteOptionErrors(t *testing.T) {
	chain, key := testPKI(t)
	in := unsignedFile(t, "small.jpg")
	if _, err := JPEG(in, &Options{Chain: chain, Signer: key, Sidecar: true}); !errors.Is(err, ErrSidecar) {
		t.Errorf("JPEG with Sidecar: %v", err)
	}
	if _, err := PNG(unsignedFile(t, "small.png"), &Options{Chain: chain, Signer: key, Sidecar: true}); !errors.Is(err, ErrSidecar) {
		t.Errorf("PNG with Sidecar: %v", err)
	}
	for _, u := range []string{"ftp://x/y", "not a url", "/relative.c2pa"} {
		if _, err := Asset(in, &Options{Chain: chain, Signer: key, RemoteURL: u}); !errors.Is(err, ErrBadRemote) {
			t.Errorf("RemoteURL %q: %v", u, err)
		}
	}
	if _, err := Asset([]byte("GIF89a"), &Options{Chain: chain, Signer: key}); !errors.Is(err, ErrFormat) {
		t.Errorf("GIF: %v", err)
	}
}

// TestC2patoolRemote: c2patool reads our sidecar next to the file, fetches
// our remote-only store from a local server, and uses the embedded store
// when both are present.
func TestC2patoolRemote(t *testing.T) {
	needC2patool(t)
	chain, key := testPKI(t)
	srv := newStoreServer(t)
	for _, name := range []string{"small.jpg", "small.png"} {
		ext := filepath.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		for _, mode := range []struct {
			label   string
			sidecar bool
			remote  bool
		}{{"sidecar", true, false}, {"remote", true, true}, {"both", false, true}} {
			dir := t.TempDir()
			opts := &Options{Chain: chain, Signer: key, Sidecar: mode.sidecar}
			if mode.remote {
				opts.RemoteURL = srv.URL + "/" + mode.label + "/" + stem + ".c2pa"
			}
			s, err := Asset(unsignedFile(t, name), opts)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, s.File, 0o644); err != nil {
				t.Fatal(err)
			}
			switch {
			case mode.remote && mode.sidecar:
				srv.put("/"+mode.label+"/"+stem+".c2pa", s.Store)
			case mode.sidecar:
				if err := os.WriteFile(filepath.Join(dir, stem+".c2pa"), s.Store, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, trusted := range []bool{false, true} {
				rep := runC2patool(t, path, trusted)
				wantState, wantFail := "Valid", []string{verify.SigningCredentialUntrusted}
				if trusted {
					wantState, wantFail = "Trusted", nil
				}
				if rep.State != wantState || !slices.Equal(rep.failures(), wantFail) {
					t.Errorf("%s %s (trusted %v): c2patool state %s, failures %q", name, mode.label, trusted, rep.State, rep.failures())
				}
			}
		}
	}
}
