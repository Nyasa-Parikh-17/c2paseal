package verify

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/fixtures"
)

// FuzzExternalStore checks that verifying a file against a manifest store
// kept outside it never panics, for both ways such a store arrives: given
// as a sidecar (Options.ManifestStore) and downloaded from the file's XMP
// dcterms:provenance URL (Options.FetchRemote).
func FuzzExternalStore(f *testing.F) {
	dir, err := fixtures.Dir()
	if err != nil {
		f.Skip(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, "remote", filepath.FromSlash(name)))
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	sidecarImage, remoteImage := read("sidecar.jpg"), read("remote.jpg")
	f.Add(read("sidecar.c2pa"))
	f.Add(read("served/remote.c2pa"))
	f.Fuzz(func(t *testing.T, store []byte) {
		r := File(sidecarImage, &Options{ManifestStore: store})
		if len(r.ActiveManifest) == 0 {
			t.Fatal("sidecar: no statuses")
		}
		_ = r.State()

		client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {MediaType}},
				Body:       io.NopCloser(bytes.NewReader(store)),
			}, nil
		})}
		r = File(remoteImage, &Options{FetchRemote: true, HTTPClient: client})
		if len(r.ActiveManifest) == 0 {
			t.Fatal("remote: no statuses")
		}
		_ = r.State()
	})
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
