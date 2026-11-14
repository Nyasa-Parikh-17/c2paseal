package fixtures

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Kind is the corpus directory a fixture lives in.
type Kind string

const (
	Unsigned Kind = "unsigned"
	Signed   Kind = "signed"
	Broken   Kind = "broken"
	Sample   Kind = "samples"
	// Remote holds files whose manifest store is outside the file: a
	// <name>.c2pa sidecar next to it, or a store in remote/served/ that
	// the file's XMP references (see RemoteClient).
	Remote Kind = "remote"
	// Legacy holds C2PA 1.x files (claim v1): some from the public c2pa-rs
	// test corpus, some written by c2patool with the test PKI.
	Legacy Kind = "legacy"
	// OCSP holds files signed by the OCSP test signers with a stapled
	// response (good, revoked, unknown) from the test responder.
	OCSP Kind = "ocsp"
)

// Kinds lists every corpus directory, in a stable order.
var Kinds = []Kind{Unsigned, Signed, Broken, Sample, Remote, Legacy, OCSP}

// Fixture is one test image and the paths of its oracle output.
type Fixture struct {
	Name   string // file name, e.g. "small.jpg"
	Kind   Kind
	Format string // "jpeg", "png" or "webp"
	Path   string

	// ExpectedPath holds c2patool --detailed output with default trust
	// (the test PKI is untrusted). TrustedPath holds the same with
	// testdata/pki/trust-anchors.pem trusted. Either may not exist.
	ExpectedPath string
	TrustedPath  string

	// SidecarPath is the fixture's <name>.c2pa manifest store, or "" if
	// there is none. ServedPath is the store in remote/served/ that a
	// remote-only fixture's XMP references, or "".
	SidecarPath string
	ServedPath  string
}

// External reports whether the fixture's manifest store is outside the
// file (a sidecar or a remote store) rather than embedded.
func (f Fixture) External() bool { return f.SidecarPath != "" || f.ServedPath != "" }

// ExternalStore returns the bytes of the fixture's sidecar or remote store,
// or nil if it is not External.
func (f Fixture) ExternalStore() ([]byte, error) {
	switch {
	case f.SidecarPath != "":
		return os.ReadFile(f.SidecarPath)
	case f.ServedPath != "":
		return os.ReadFile(f.ServedPath)
	}
	return nil, nil
}

// RemoteClient returns an HTTP client that answers every request with the
// file of the same base name in testdata/remote/served, as the server in
// scripts/make-remote-fixtures.sh did, without opening a network port.
func RemoteClient() (*http.Client, error) {
	root, err := Dir()
	if err != nil {
		return nil, err
	}
	served := filepath.Join(root, string(Remote), "served")
	return &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		b, err := os.ReadFile(filepath.Join(served, path.Base(r.URL.Path)))
		status := http.StatusOK
		if err != nil {
			b, status = nil, http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(bytes.NewReader(b)),
			Header: http.Header{}, Request: r, ContentLength: int64(len(b))}, nil
	})}, nil
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// String returns "kind/name", for subtest names.
func (f Fixture) String() string { return string(f.Kind) + "/" + f.Name }

// Expected loads the default-trust oracle output.
func (f Fixture) Expected() (*Expected, error) { return load(f.ExpectedPath) }

// Trusted loads the oracle output produced with the test root trusted.
func (f Fixture) Trusted() (*Expected, error) { return load(f.TrustedPath) }

// Expected is the decoded output of `c2patool <file> --detailed`. Fields not
// modelled here remain available in Raw.
type Expected struct {
	ActiveManifest    string                     `json:"active_manifest"`
	Manifests         map[string]json.RawMessage `json:"manifests"`
	ValidationResults *ValidationResults         `json:"validation_results"`
	ValidationState   string                     `json:"validation_state"`

	// Set instead of the fields above when c2patool exited with an error.
	C2patoolError string `json:"c2patool_error"`
	ExitCode      int    `json:"exit_code"`

	Raw json.RawMessage `json:"-"`
}

// ValidationResults groups status codes for the active manifest and for
// ingredients.
type ValidationResults struct {
	ActiveManifest   *StatusGroup    `json:"activeManifest"`
	IngredientDeltas json.RawMessage `json:"ingredientDeltas"`
}

// StatusGroup holds C2PA validation statuses by kind.
type StatusGroup struct {
	Success       []Status `json:"success"`
	Informational []Status `json:"informational"`
	Failure       []Status `json:"failure"`
}

// Status is one C2PA validation status entry.
type Status struct {
	Code        string `json:"code"`
	URL         string `json:"url"`
	Explanation string `json:"explanation"`
}

// Failed reports whether c2patool could not read the file at all.
func (e *Expected) Failed() bool { return e.C2patoolError != "" }

// ManifestLabels returns the labels of every manifest in the store, sorted.
func (e *Expected) ManifestLabels() []string {
	labels := make([]string, 0, len(e.Manifests))
	for l := range e.Manifests {
		labels = append(labels, l)
	}
	slices.Sort(labels)
	return labels
}

// Codes returns every status code for the active manifest: success, then
// informational, then failure, each in oracle order.
func (e *Expected) Codes() []string {
	if e.ValidationResults == nil || e.ValidationResults.ActiveManifest == nil {
		return nil
	}
	g := e.ValidationResults.ActiveManifest
	var codes []string
	for _, list := range [][]Status{g.Success, g.Informational, g.Failure} {
		for _, s := range list {
			codes = append(codes, s.Code)
		}
	}
	return codes
}

func load(path string) (*Expected, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fixtures: %w", err)
	}
	var e Expected
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("fixtures: decode %s: %w", path, err)
	}
	e.Raw = b
	return &e, nil
}

// Dir returns the repository's testdata directory, found by walking up from
// the working directory to go.mod.
func Dir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("fixtures: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("fixtures: go.mod not found above working directory")
		}
		dir = parent
	}
}

// List returns every JPEG and PNG fixture in the corpus, ordered by kind and
// then name.
func List() ([]Fixture, error) {
	root, err := Dir()
	if err != nil {
		return nil, err
	}
	var out []Fixture
	for _, k := range Kinds {
		entries, err := os.ReadDir(filepath.Join(root, string(k)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("fixtures: %w", err)
		}
		for _, e := range entries {
			format := formatOf(e.Name())
			if e.IsDir() || format == "" {
				continue
			}
			p := filepath.Join(root, string(k), e.Name())
			f := Fixture{
				Name:         e.Name(),
				Kind:         k,
				Format:       format,
				Path:         p,
				ExpectedPath: p + ".expected.json",
				TrustedPath:  p + ".trusted.expected.json",
			}
			stem := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			if sc := filepath.Join(root, string(k), stem+".c2pa"); fileExists(sc) {
				f.SidecarPath = sc
			} else if sv := filepath.Join(root, string(k), "served", stem+".c2pa"); k == Remote && fileExists(sv) {
				f.ServedPath = sv
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// ListKind returns the fixtures of one kind.
func ListKind(k Kind) ([]Fixture, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(f Fixture) bool { return f.Kind != k }), nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func formatOf(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg":
		return "jpeg"
	case ".png":
		return "png"
	case ".webp":
		return "webp"
	}
	return ""
}
