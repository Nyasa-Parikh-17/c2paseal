package manifest

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/Nyasa-Parikh-17/c2paseal/container/jumbf"
)

// JUMBFURIPrefix starts every C2PA internal reference.
const JUMBFURIPrefix = "self#jumbf="

// DefaultAlg is used when neither a hashed URI nor its claim names one.
const DefaultAlg = "sha256"

// URI errors.
var (
	ErrBadURI         = errors.New("not a self#jumbf= URI")
	ErrUnresolved     = errors.New("URI does not resolve to a box")
	ErrUnsupportedAlg = errors.New("unsupported hash algorithm")
)

// Resolve finds the box a self#jumbf= URI names. Absolute URIs
// ("self#jumbf=/c2pa/…") start at the store root; relative ones
// ("self#jumbf=c2pa.assertions/…") at the manifest.
func Resolve(root, manifest *jumbf.Box, uri string) (*jumbf.Box, error) {
	path, ok := strings.CutPrefix(uri, JUMBFURIPrefix)
	if !ok || path == "" {
		return nil, fmt.Errorf("manifest: %w: %q", ErrBadURI, uri)
	}
	var b *jumbf.Box
	if abs, ok := strings.CutPrefix(path, "/"); ok {
		b = root.Find(abs)
	} else {
		b = manifest.Find(manifest.Label() + "/" + path)
	}
	if b == nil {
		return nil, fmt.Errorf("manifest: %w: %q", ErrUnresolved, uri)
	}
	return b, nil
}

// NewHash returns a hash for a C2PA algorithm name.
func NewHash(alg string) (hash.Hash, error) {
	switch alg {
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("manifest: %w: %q", ErrUnsupportedAlg, alg)
}

// HashBox hashes a JUMBF box the way hashed URIs do: the box's contents
// (description box and content boxes) without its own LBox/TBox header.
func HashBox(alg string, b *jumbf.Box) ([]byte, error) {
	h, err := NewHash(alg)
	if err != nil {
		return nil, err
	}
	h.Write(b.Bytes()[b.HeaderLen():])
	return h.Sum(nil), nil
}

// URICheck is the result of checking one hashed URI from a claim.
type URICheck struct {
	Ref   HashedURI
	Alg   string     // algorithm used: Ref.Alg, else the claim's, else sha256
	Box   *jumbf.Box // nil if the URI did not resolve
	Match bool
	Err   error // ErrBadURI, ErrUnresolved or ErrUnsupportedAlg
}

// checkRefs resolves and hashes every assertion reference in m's claim.
func checkRefs(root *jumbf.Box, m *Manifest) []URICheck {
	var out []URICheck
	for _, ref := range m.Claim.Assertions() {
		c := URICheck{Ref: ref, Alg: cmp.Or(ref.Alg, m.Claim.Alg, DefaultAlg)}
		c.Box, c.Err = Resolve(root, m.Box, ref.URL)
		if c.Err == nil {
			var sum []byte
			if sum, c.Err = HashBox(c.Alg, c.Box); c.Err == nil {
				c.Match = bytes.Equal(sum, ref.Hash)
			}
		}
		out = append(out, c)
	}
	return out
}
