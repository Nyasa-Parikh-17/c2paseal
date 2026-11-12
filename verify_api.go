package c2paseal

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// VerifyOptions configures Verify. TrustAnchors lists the certificates a
// signer must chain to; with none, signers are reported as untrusted.
type VerifyOptions = verify.Options

// Status is one C2PA validation status (code, URL, explanation).
type Status = verify.Status

// Verify validates the C2PA manifest store of a JPEG or PNG file and returns
// every status: the active manifest's, then any ingredient deltas. Missing,
// unreadable and malformed files give failure statuses, never an error.
func Verify(path string, opts *VerifyOptions) []Status {
	return VerifyFile(path, opts).Statuses()
}

// VerifyFile is Verify returning the grouped result, which also gives the
// overall State (Invalid, Valid or Trusted).
//
// A file without an embedded store is checked against its sidecar
// (SidecarPath(path)) if there is one and VerifyOptions.ManifestStore is
// not set; failing that, against the remote store its XMP references, if
// VerifyOptions.FetchRemote is set.
func VerifyFile(path string, opts *VerifyOptions) *verify.Result {
	b, err := os.ReadFile(path)
	if err != nil {
		return &verify.Result{ActiveManifest: []Status{{Code: verify.GeneralError, Explanation: err.Error()}}}
	}
	if sidecar, ok := findSidecar(path, b, opts); ok {
		o := VerifyOptions{}
		if opts != nil {
			o = *opts
		}
		o.ManifestStore = sidecar
		opts = &o
	}
	return VerifyBytes(b, opts)
}

// findSidecar returns the sidecar store of a file that has no embedded one.
func findSidecar(path string, b []byte, opts *VerifyOptions) ([]byte, bool) {
	if opts != nil && opts.ManifestStore != nil {
		return nil, false
	}
	if _, _, err := asset.Extract(b); !errors.Is(err, asset.ErrNoManifest) {
		return nil, false
	}
	sc := SidecarPath(path)
	if sc == path {
		return nil, false
	}
	store, err := os.ReadFile(sc)
	if err != nil {
		return nil, false
	}
	return store, true
}

// VerifyBytes is VerifyFile for a file already in memory.
func VerifyBytes(b []byte, opts *VerifyOptions) *verify.Result {
	return verify.File(b, opts)
}

// LoadTrustAnchors reads PEM-encoded certificates for VerifyOptions.TrustAnchors.
func LoadTrustAnchors(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: trust anchors: %w", err)
	}
	var out []*x509.Certificate
	for blk, rest := pem.Decode(b); blk != nil; blk, rest = pem.Decode(rest) {
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("c2paseal: trust anchors: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("c2paseal: trust anchors: no PEM certificates in " + path)
	}
	return out, nil
}
