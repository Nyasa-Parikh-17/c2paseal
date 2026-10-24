package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
)

// Defaults for Options.
const (
	DefaultGenerator         = "C2paSeal"
	DefaultGeneratorVersion  = "0.1.0"
	DefaultDigitalSourceType = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
)

// Options configures a manifest.
type Options struct {
	// Chain is the signing certificate followed by its intermediates (not
	// the root). Signer holds the private key of Chain[0]. Only ECDSA P-256
	// (ES256) is supported.
	Chain  []*x509.Certificate
	Signer crypto.Signer

	// Claim generator name and version; defaults DefaultGenerator and
	// DefaultGeneratorVersion.
	Generator        string
	GeneratorVersion string

	// Actions for the c2pa.actions.v2 assertion. Nil means one c2pa.created
	// action with DigitalSourceType (default DefaultDigitalSourceType).
	Actions           []assertion.Action
	DigitalSourceType string

	// Title is the optional dc:title of the claim.
	Title string

	// Thumbnail is an optional claim thumbnail (c2pa.thumbnail.claim).
	Thumbnail *assertion.Thumbnail

	// Rand supplies randomness for salts and UUIDs; nil means crypto/rand.
	// Signatures always use crypto/rand.
	Rand io.Reader
}

// Option errors.
var (
	ErrNoSigner     = errors.New("sign: no signing certificate or key")
	ErrKeyMismatch  = errors.New("sign: private key does not match the signing certificate")
	ErrUnsupported  = errors.New("sign: only ECDSA P-256 (ES256) keys are supported")
	ErrBadActions   = errors.New("sign: invalid actions")
	ErrBadThumbnail = errors.New("sign: thumbnail needs a media type and data")
)

func (o *Options) rand() io.Reader {
	if o.Rand != nil {
		return o.Rand
	}
	return rand.Reader
}

func (o *Options) generator() (string, string) {
	name, version := o.Generator, o.GeneratorVersion
	if name == "" {
		name, version = DefaultGenerator, DefaultGeneratorVersion
		if o.GeneratorVersion != "" {
			version = o.GeneratorVersion
		}
	}
	return name, version
}

// actions returns the actions to record, applying the default.
func (o *Options) actions() []assertion.Action {
	if o.Actions != nil {
		return o.Actions
	}
	src := o.DigitalSourceType
	if src == "" {
		src = DefaultDigitalSourceType
	}
	return []assertion.Action{{Action: "c2pa.created", DigitalSourceType: src}}
}

// validate checks Options before anything is built, so Sign never writes a
// manifest that C2PA validators reject for its structure.
func (o *Options) validate() error {
	if len(o.Chain) == 0 || o.Chain[0] == nil || o.Signer == nil {
		return ErrNoSigner
	}
	pub, ok := o.Chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return ErrUnsupported
	}
	if signerPub, ok := o.Signer.Public().(*ecdsa.PublicKey); !ok || !signerPub.Equal(pub) {
		return ErrKeyMismatch
	}

	acts := o.actions()
	if len(acts) == 0 {
		return fmt.Errorf("%w: no actions", ErrBadActions)
	}
	for i, a := range acts {
		switch {
		case a.Action == "":
			return fmt.Errorf("%w: action %d has no name", ErrBadActions, i)
		case i == 0 && a.Action != "c2pa.created":
			// c2pa.opened would need an ingredient, which is out of MVP scope.
			return fmt.Errorf("%w: first action must be c2pa.created", ErrBadActions)
		case i > 0 && (a.Action == "c2pa.created" || a.Action == "c2pa.opened"):
			return fmt.Errorf("%w: %s must be the first action", ErrBadActions, a.Action)
		case a.Action == "c2pa.created" && a.DigitalSourceType == "":
			return fmt.Errorf("%w: c2pa.created needs a digitalSourceType", ErrBadActions)
		case a.Action == "c2pa.placed" || a.Action == "c2pa.removed":
			return fmt.Errorf("%w: %s needs an ingredient (not supported)", ErrBadActions, a.Action)
		}
	}
	if t := o.Thumbnail; t != nil && (t.Format == "" || len(t.Data) == 0) {
		return ErrBadThumbnail
	}
	return nil
}
