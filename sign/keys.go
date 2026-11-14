package sign

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
)

// A KeyProvider opens signing keys named by URIs of one scheme, so a key
// does not have to be a file on disk: it can live in a cloud KMS, for
// example. The signer it returns is used as Options.Signer; it must sign
// SHA-256 digests with ECDSA P-256 (ES256) and return ASN.1 DER signatures,
// as crypto/ecdsa does.
//
// This package has the file: provider built in. Others register themselves
// when imported, as database/sql drivers do:
//
//	import _ "github.com/Nyasa-Parikh-17/c2paseal/keys/awskms" // awskms:
//	import _ "github.com/Nyasa-Parikh-17/c2paseal/keys/gcpkms" // gcpkms:
//
// Those live in their own Go modules, so their SDKs are not dependencies of
// this one.
type KeyProvider interface {
	// Open returns the signer for uri, whose scheme is the provider's. ctx
	// bounds the work Open does (such as fetching the public key); it is
	// not kept for later signing calls.
	Open(ctx context.Context, uri *url.URL) (crypto.Signer, error)
}

var (
	providersMu sync.RWMutex
	providers   = map[string]KeyProvider{"file": fileProvider{}}
)

// knownModules names where the providers of known schemes live, for the
// error when one is used without being imported.
var knownModules = map[string]string{
	"awskms": "github.com/Nyasa-Parikh-17/c2paseal/keys/awskms",
	"gcpkms": "github.com/Nyasa-Parikh-17/c2paseal/keys/gcpkms",
}

// RegisterKeyProvider makes p open URIs with the given scheme (lower case,
// without the colon). It panics if the scheme is already registered or p is
// nil, as database/sql.Register does.
func RegisterKeyProvider(scheme string, p KeyProvider) {
	providersMu.Lock()
	defer providersMu.Unlock()
	if p == nil {
		panic("sign: RegisterKeyProvider with a nil provider")
	}
	scheme = strings.ToLower(scheme)
	if _, dup := providers[scheme]; dup {
		panic("sign: RegisterKeyProvider called twice for scheme " + scheme)
	}
	providers[scheme] = p
}

// KeySchemes returns the registered schemes, sorted.
func KeySchemes() []string {
	providersMu.RLock()
	defer providersMu.RUnlock()
	var s []string
	for k := range providers {
		s = append(s, k)
	}
	slices.Sort(s)
	return s
}

// OpenKey opens the signing key that uri names:
//
//	key.pem, ./keys/key.pem, C:\keys\key.pem   a PEM file (no scheme)
//	file:key.pem, file:///etc/c2pa/key.pem     a PEM file
//	awskms:<key ARN, key ID or alias>[?region=…]           (keys/awskms)
//	gcpkms:projects/…/cryptoKeyVersions/<n>               (keys/gcpkms)
//
// A PEM file holds a PKCS #8 or SEC 1 EC private key (see ParsePrivateKey).
func OpenKey(ctx context.Context, uri string) (crypto.Signer, error) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme == "" || isDrive(uri) {
		// A plain path: "key.pem", "/etc/key.pem", `C:\key.pem`.
		return openKeyFile(uri)
	}
	scheme := strings.ToLower(u.Scheme)
	providersMu.RLock()
	p := providers[scheme]
	providersMu.RUnlock()
	if p == nil {
		if mod, ok := knownModules[scheme]; ok {
			return nil, fmt.Errorf("sign: key %s: the %s: provider is not linked into this program; import %s", redact(u), scheme, mod)
		}
		return nil, fmt.Errorf("sign: key %s: no key provider for scheme %q (have %s)", redact(u), scheme, strings.Join(KeySchemes(), ", "))
	}
	s, err := p.Open(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("sign: key %s: %w", redact(u), err)
	}
	return s, nil
}

// redact drops a URI's user info and query from error messages, in case
// they carry credentials.
func redact(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	return c.String()
}

// isDrive reports whether s starts with a Windows drive letter ("C:"),
// which url.Parse reads as a scheme.
func isDrive(s string) bool {
	return len(s) >= 2 && s[1] == ':' && (s[0]|0x20) >= 'a' && (s[0]|0x20) <= 'z' && (len(s) == 2 || s[2] == '\\' || s[2] == '/')
}

// fileProvider opens file: URIs.
type fileProvider struct{}

func (fileProvider) Open(_ context.Context, u *url.URL) (crypto.Signer, error) {
	var p string
	switch {
	case u.Opaque != "": // file:key.pem, file:keys/key.pem
		p = u.Opaque
	case u.Host != "" && u.Host != "localhost":
		return nil, errors.New("file: URIs with a host are not supported")
	default: // file:///etc/key.pem, file:///C:/keys/key.pem
		p = u.Path
		if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && isDrive(p[1:]) {
			p = p[1:]
		}
	}
	if p == "" {
		return nil, errors.New("file: URI without a path")
	}
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	return openKeyFile(filepath.FromSlash(p))
}

func openKeyFile(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sign: key: %w", err)
	}
	s, err := ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, path)
	}
	return s, nil
}

// ParsePrivateKey parses the first PEM block of b as a private key: SEC 1
// ("EC PRIVATE KEY") or PKCS #8.
func ParsePrivateKey(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("sign: key: no PEM block")
	}
	var key any
	var err error
	switch blk.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("sign: key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("sign: key: %T cannot sign", key)
	}
	return signer, nil
}
