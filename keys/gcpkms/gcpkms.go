// Package gcpkms signs C2PA manifests with ES256 keys held in Google Cloud
// KMS. The private key never leaves KMS: C2paSeal sends it the SHA-256
// digest to sign.
//
// Importing the package registers the gcpkms: scheme with sign.OpenKey:
//
//	import _ "github.com/Nyasa-Parikh-17/c2paseal/keys/gcpkms"
//
//	signer, err := sign.OpenKey(ctx, "gcpkms:projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
//
// The URI is gcpkms:<key version name>[?endpoint=<url>]. The key version
// must have the algorithm EC_SIGN_P256_SHA256. Credentials are Application
// Default Credentials (GOOGLE_APPLICATION_CREDENTIALS, gcloud's login, or
// the metadata server). endpoint overrides the KMS endpoint; an http://
// endpoint (a local emulator) is called without credentials, so tokens are
// never sent in the clear. The caller needs
// cloudkms.cryptoKeyVersions.viewPublicKey once and
// cloudkms.cryptoKeyVersions.useToSign for each signature.
//
// Requests and responses carry CRC32C checksums, which are checked as
// Google recommends, and each signature is verified against the public key
// before it is used.
//
// This is its own Go module, so the Google Cloud SDK is not a dependency of
// the core C2paSeal module.
package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Scheme is the key URI scheme this package registers.
const Scheme = "gcpkms"

func init() { sign.RegisterKeyProvider(Scheme, Provider{}) }

// Client is the part of *kms.KeyManagementClient a Signer uses.
type Client interface {
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// Signer is a crypto.Signer whose private key is a Cloud KMS key version.
type Signer struct {
	client Client
	closer io.Closer // the client, when the Signer created it
	name   string
	pub    *ecdsa.PublicKey
	// Timeout bounds each AsymmetricSign call (crypto.Signer has no
	// context). New sets it to 30 seconds.
	Timeout time.Duration
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc32c(b []byte) int64 { return int64(crc32.Checksum(b, castagnoli)) }

// versionName matches a full key version resource name.
var versionName = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`)

// New returns a Signer for the key version name. It fetches the public key
// and checks that the key version can sign ES256.
func New(ctx context.Context, client Client, name string) (*Signer, error) {
	if !versionName.MatchString(name) {
		return nil, fmt.Errorf("gcpkms: %q is not a key version name (projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/…)", name)
	}
	pk, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("gcpkms: get public key: %w", err)
	}
	if pk.GetName() != "" && pk.GetName() != name {
		return nil, fmt.Errorf("gcpkms: public key response is for %s, not %s", pk.GetName(), name)
	}
	if pk.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
		return nil, fmt.Errorf("gcpkms: algorithm is %s; C2paSeal signs ES256 and needs EC_SIGN_P256_SHA256", pk.GetAlgorithm())
	}
	if c := pk.GetPemCrc32C(); c != nil && c.GetValue() != crc32c([]byte(pk.GetPem())) {
		return nil, errors.New("gcpkms: public key corrupted in transit (CRC32C mismatch)")
	}
	blk, _ := pem.Decode([]byte(pk.GetPem()))
	if blk == nil {
		return nil, errors.New("gcpkms: public key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: parse public key: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("gcpkms: public key is %T, want ECDSA P-256", k)
	}
	return &Signer{client: client, name: name, pub: pub, Timeout: 30 * time.Second}, nil
}

// Name returns the key version's resource name.
func (s *Signer) Name() string { return s.name }

// Public returns the key's public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign asks KMS to sign a SHA-256 digest and returns the ASN.1 DER
// signature, after checking its checksums and verifying it against the
// public key.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// go-cose passes nil opts, as crypto/ecdsa allows; the digest length
	// still has to be SHA-256's.
	if (opts != nil && opts.HashFunc() != crypto.SHA256) || len(digest) != 32 {
		return nil, errors.New("gcpkms: only SHA-256 digests can be signed (ES256)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:         s.name,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
		DigestCrc32C: wrapperspb.Int64(crc32c(digest)),
	})
	if err != nil {
		return nil, fmt.Errorf("gcpkms: sign: %w", err)
	}
	switch {
	case !resp.GetVerifiedDigestCrc32C():
		return nil, errors.New("gcpkms: digest corrupted in transit (KMS did not verify its CRC32C)")
	case resp.GetName() != s.name:
		return nil, fmt.Errorf("gcpkms: signature response is for %s, not %s", resp.GetName(), s.name)
	case resp.GetSignatureCrc32C().GetValue() != crc32c(resp.GetSignature()):
		return nil, errors.New("gcpkms: signature corrupted in transit (CRC32C mismatch)")
	case !ecdsa.VerifyASN1(s.pub, digest, resp.GetSignature()):
		return nil, errors.New("gcpkms: KMS returned a signature that does not verify with the key's public key")
	}
	return resp.GetSignature(), nil
}

// Close closes the KMS client if Provider.Open created it.
func (s *Signer) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// Provider opens gcpkms: URIs (see the package documentation). It is
// registered with sign.RegisterKeyProvider when the package is imported.
type Provider struct{}

// Open implements sign.KeyProvider. The returned *Signer holds a KMS client
// until its Close method is called.
func (Provider) Open(ctx context.Context, u *url.URL) (crypto.Signer, error) {
	name := u.Opaque
	if name == "" { // gcpkms://projects/… or gcpkms:///projects/…
		name = strings.TrimPrefix(u.Host+u.Path, "/")
	}
	if name == "" {
		return nil, errors.New("gcpkms: URI names no key version")
	}
	var opts []option.ClientOption
	if e := u.Query().Get("endpoint"); e != "" {
		eu, err := url.Parse(e)
		if err != nil || (eu.Scheme != "https" && eu.Scheme != "http") || eu.Host == "" {
			return nil, fmt.Errorf("gcpkms: endpoint %q is not an http(s) URL", e)
		}
		opts = append(opts, option.WithEndpoint(e))
		if eu.Scheme == "http" {
			opts = append(opts, option.WithoutAuthentication())
		}
	}
	client, err := kms.NewKeyManagementRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: client: %w", err)
	}
	s, err := New(ctx, client, name)
	if err != nil {
		client.Close()
		return nil, err
	}
	s.closer = client
	return s, nil
}
