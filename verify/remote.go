package verify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
)

// MaxRemoteStore bounds the size of a downloaded manifest store.
const MaxRemoteStore = 64 << 20

// MediaType is the media type of a manifest store served on its own
// (C2PA 2.4 §11.4).
const MediaType = "application/c2pa"

// external finds the manifest store of a file that has none embedded, in
// the order of C2PA 2.4 §15.5.3: Options.ManifestStore (a sidecar), then
// the XMP dcterms:provenance URL. It returns the parsed store, or the one
// failure status to report instead.
func external(b []byte, opts *Options) (*jumbf.Box, *Status) {
	if opts != nil && opts.ManifestStore != nil {
		return parseExternal(opts.ManifestStore, "")
	}
	url, ok, err := asset.RemoteURL(b)
	if err != nil {
		return nil, &Status{Code: GeneralError, Explanation: "XMP could not be read: " + err.Error()}
	}
	if !ok {
		return nil, &Status{Code: ClaimMissing, Explanation: "could not find active manifest"}
	}
	if opts == nil || !opts.FetchRemote {
		return nil, &Status{ManifestInaccessible, url, "remote manifest not fetched: remote fetching is off"}
	}
	store, err := fetch(opts, url)
	if err != nil {
		return nil, &Status{ManifestInaccessible, url, "remote manifest could not be fetched: " + err.Error()}
	}
	return parseExternal(store, url)
}

func parseExternal(store []byte, url string) (*jumbf.Box, *Status) {
	root, err := jumbf.Parse(store)
	if err != nil {
		return nil, &Status{ClaimMalformed, url, "manifest store could not be parsed: " + err.Error()}
	}
	return root, nil
}

// fetch downloads a remote manifest store.
func fetch(opts *Options, url string) ([]byte, error) {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", MediaType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxRemoteStore+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxRemoteStore {
		return nil, fmt.Errorf("manifest store larger than %d bytes", MaxRemoteStore)
	}
	return body, nil
}
