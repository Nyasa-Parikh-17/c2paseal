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
	"net/http"
	"net/url"

	"github.com/Nyasa-Parikh-17/c2paseal/manifest/assertion"
	"github.com/Nyasa-Parikh-17/c2paseal/verify"
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
	// action with DigitalSourceType (default DefaultDigitalSourceType), or,
	// when the input already has a manifest store, one c2pa.opened action.
	//
	// When the input has a manifest store (and NoHistory is not set), the
	// first action is c2pa.opened, referencing the parent ingredient; it is
	// added if Actions does not start with it, and c2pa.created is not
	// allowed.
	Actions           []assertion.Action
	DigitalSourceType string

	// NoHistory makes signing replace an existing manifest store instead
	// of recording it as the parent ingredient (the v0.1 behaviour).
	NoHistory bool
	// ParentVerify configures the validation of an existing manifest store
	// whose results are recorded in the parent ingredient. Nil means no
	// trust anchors, as c2patool does by default.
	ParentVerify *verify.Options

	// RemoteURL, if set, is written into the file's XMP as
	// dcterms:provenance: the URL where the manifest store will be served
	// (C2PA 2.4 §11.5). The store is still embedded unless Sidecar is set.
	RemoteURL string
	// Sidecar leaves the manifest store out of the file. Use Asset, which
	// returns the store, to save it as a .c2pa sidecar or serve it at
	// RemoteURL. The hard binding then covers the whole file.
	Sidecar bool

	// Title is the optional dc:title of the claim.
	Title string

	// Thumbnail is an optional claim thumbnail (c2pa.thumbnail.claim).
	Thumbnail *assertion.Thumbnail

	// TSAURL, if set, is an RFC 3161 time-stamp authority. The signature is
	// time-stamped and the token stored as sigTst2 in the COSE unprotected
	// header, so validators can check the signer against the TSA's time
	// instead of the current time.
	TSAURL string
	// TSAClient sends time-stamp requests; nil means an http.Client with a
	// 30-second timeout.
	TSAClient *http.Client
	// TimestampReserve is the largest token, in bytes, that the manifest
	// reserves room for; zero means DefaultTimestampReserve. The reserved
	// space is in the file whatever the real token's size.
	TimestampReserve int

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
	ErrBadTSA       = errors.New("sign: invalid time-stamp options")
	ErrBadRemote    = errors.New("sign: invalid remote manifest URL")
)

func (o *Options) rand() io.Reader {
	if o.Rand != nil {
		return o.Rand
	}
	return rand.Reader
}

func (o *Options) timestampReserve() int {
	if o.TimestampReserve == 0 {
		return DefaultTimestampReserve
	}
	return o.TimestampReserve
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

// actions returns the actions to record, applying the defaults. With a
// parent, the list starts with c2pa.opened, whose ingredients parameter
// the builder fills in.
func (o *Options) actions(hasParent bool) []assertion.Action {
	if hasParent {
		acts := []assertion.Action{{Action: actionOpened}}
		if len(o.Actions) > 0 && o.Actions[0].Action == actionOpened {
			acts[0] = o.Actions[0]
			return append(acts, o.Actions[1:]...)
		}
		return append(acts, o.Actions...)
	}
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
// manifest that C2PA validators reject for its structure. hasParent says
// whether the input's manifest store becomes the parent ingredient.
func (o *Options) validate(hasParent bool) error {
	if err := o.validateSigner(); err != nil {
		return err
	}

	if hasParent && o.DigitalSourceType != "" {
		return fmt.Errorf("%w: %s", ErrBadActions, errHasHistory)
	}
	acts := o.actions(hasParent)
	if len(acts) == 0 {
		return fmt.Errorf("%w: no actions", ErrBadActions)
	}
	first := actionCreated
	if hasParent {
		first = actionOpened
	}
	for i, a := range acts {
		switch {
		case a.Action == "":
			return fmt.Errorf("%w: action %d has no name", ErrBadActions, i)
		case hasParent && a.Action == actionCreated:
			return fmt.Errorf("%w: %s", ErrBadActions, errHasHistory)
		case i == 0 && a.Action != first:
			return fmt.Errorf("%w: first action must be %s", ErrBadActions, first)
		case i > 0 && (a.Action == actionCreated || a.Action == actionOpened):
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
	if o.TimestampReserve < 0 || o.TimestampReserve > MaxTimestampReserve {
		return fmt.Errorf("%w: reserve %d bytes not in 0..%d", ErrBadTSA, o.TimestampReserve, MaxTimestampReserve)
	}
	if o.TSAURL != "" && !isHTTPURL(o.TSAURL) {
		return fmt.Errorf("%w: TSA URL %q is not an http(s) URL", ErrBadTSA, o.TSAURL)
	}
	if o.RemoteURL != "" && !isHTTPURL(o.RemoteURL) {
		return fmt.Errorf("%w: %q is not an http(s) URL", ErrBadRemote, o.RemoteURL)
	}
	return nil
}

// validateSigner checks the certificate and key, which needs nothing from
// the input file.
func (o *Options) validateSigner() error {
	if o == nil || len(o.Chain) == 0 || o.Chain[0] == nil || o.Signer == nil {
		return ErrNoSigner
	}
	pub, ok := o.Chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return ErrUnsupported
	}
	if signerPub, ok := o.Signer.Public().(*ecdsa.PublicKey); !ok || !signerPub.Equal(pub) {
		return ErrKeyMismatch
	}
	return nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

const (
	actionCreated = "c2pa.created"
	actionOpened  = "c2pa.opened"
)

// errHasHistory explains why c2pa.created cannot be used when re-signing.
const errHasHistory = "the file already has Content Credentials, so it is recorded as the parent and the first action is c2pa.opened; " +
	"set NoHistory to replace them and start a new history with c2pa.created"
