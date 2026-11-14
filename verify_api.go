package c2paseal

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/internal/asset"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
)

// VerifyOptions configures Verify. TrustAnchors lists the certificates a
// signer must chain to; with none, signers are reported as untrusted.
type VerifyOptions = verify.Options

// Status is one C2PA validation status (code, URL, explanation).
type Status = verify.Status

// Verify validates the C2PA manifest store of a JPEG, PNG or WebP file and returns
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
	return parseTrustAnchors(b, path)
}

// parseTrustAnchors is LoadTrustAnchors on the file's bytes; name is used
// in errors.
func parseTrustAnchors(b []byte, name string) ([]*x509.Certificate, error) {
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
		return nil, errors.New("c2paseal: trust anchors: no PEM certificates in " + name)
	}
	return out, nil
}

// LoadTrustList reads a C2PA trust list, a PEM bundle of trust anchors such
// as the official C2PA-TRUST-LIST.pem and C2PA-TSA-TRUST-LIST.pem from
// github.com/c2pa-org/conformance-public. Several lists can be loaded and
// appended to VerifyOptions.TrustAnchors; time-stamp authorities are
// checked against the same anchors, as in c2pa-rs.
func LoadTrustList(path string) ([]*x509.Certificate, error) { return LoadTrustAnchors(path) }

// ParseTrustAnchors is LoadTrustAnchors (and LoadTrustList) on the PEM
// bytes, for callers without files (such as the WebAssembly build).
func ParseTrustAnchors(b []byte) ([]*x509.Certificate, error) {
	return parseTrustAnchors(b, "the input")
}

// LoadAllowedList reads an allowed list for VerifyOptions.AllowedList, in
// c2pa-rs's format: PEM certificates, and lines outside PEM blocks that are
// the base64 SHA-256 of a certificate's DER (44 characters). Other lines are
// ignored.
func LoadAllowedList(path string) ([][sha256.Size]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: allowed list: %w", err)
	}
	return parseAllowedList(b, path)
}

// ParseAllowedList is LoadAllowedList on the file's bytes.
func ParseAllowedList(b []byte) ([][sha256.Size]byte, error) {
	return parseAllowedList(b, "the input")
}

// parseAllowedList is LoadAllowedList on the file's bytes; name is used in
// errors.
func parseAllowedList(b []byte, name string) ([][sha256.Size]byte, error) {
	var out [][sha256.Size]byte
	inside := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "-----BEGIN"):
			inside = true
		case strings.Contains(line, "-----END"):
			inside = false
		case !inside && len(line) == 44:
			if h, err := base64.StdEncoding.DecodeString(line); err == nil && len(h) == sha256.Size {
				out = append(out, [sha256.Size]byte(h))
			}
		}
	}
	for blk, rest := pem.Decode(b); blk != nil; blk, rest = pem.Decode(rest) {
		if blk.Type == "CERTIFICATE" {
			out = append(out, sha256.Sum256(blk.Bytes))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("c2paseal: allowed list: no certificates or hashes in " + name)
	}
	return out, nil
}

// LoadTrustConfig reads a trust configuration for VerifyOptions.ExtraEKUs:
// one EKU object identifier per line (as in c2pa-rs's valid_eku_oids.cfg);
// lines that are not OIDs, such as comments, are ignored.
func LoadTrustConfig(path string) ([]asn1.ObjectIdentifier, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("c2paseal: trust config: %w", err)
	}
	return parseTrustConfig(b), nil
}

// ParseTrustConfig is LoadTrustConfig on the file's bytes.
func ParseTrustConfig(b []byte) []asn1.ObjectIdentifier { return parseTrustConfig(b) }

// parseTrustConfig is LoadTrustConfig on the file's bytes.
func parseTrustConfig(b []byte) []asn1.ObjectIdentifier {
	var out []asn1.ObjectIdentifier
	for _, line := range strings.Split(string(b), "\n") {
		if oid, ok := parseOID(strings.TrimSpace(line)); ok {
			out = append(out, oid)
		}
	}
	return out
}

// parseOID parses dotted decimal with at least two arcs.
func parseOID(s string) (asn1.ObjectIdentifier, bool) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, false
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return nil, false
		}
		oid[i] = n
	}
	return oid, oid[0] <= 2
}
