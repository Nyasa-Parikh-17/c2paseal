// Package awskms signs C2PA manifests with ES256 keys held in AWS KMS.
// The private key never leaves KMS: C2paSeal sends it the SHA-256 digest
// to sign.
//
// Importing the package registers the awskms: scheme with sign.OpenKey:
//
//	import _ "github.com/Nyasa-Parikh-17/c2paseal/keys/awskms"
//
//	signer, err := sign.OpenKey(ctx, "awskms:arn:aws:kms:eu-west-1:111122223333:key/1234abcd-…")
//
// The URI is awskms:<key>[?region=<region>][&profile=<name>][&endpoint=<url>]
// where <key> is a key ARN, key ID, alias name ("alias/c2pa-signing") or
// alias ARN. The key must be asymmetric, ECC_NIST_P256, with key usage
// SIGN_VERIFY. Credentials come from the AWS SDK's default chain
// (environment, shared config and credentials files, SSO, IAM roles); the
// region from the ARN, the region parameter or that chain; profile picks a
// shared-config profile; endpoint overrides the KMS endpoint (a VPC
// endpoint, or a local KMS for testing). The caller needs kms:GetPublicKey
// once and kms:Sign for each signature.
//
// This is its own Go module, so the AWS SDK is not a dependency of the
// core C2paSeal module.
package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Scheme is the key URI scheme this package registers.
const Scheme = "awskms"

func init() { sign.RegisterKeyProvider(Scheme, Provider{}) }

// Client is the part of *kms.Client a Signer uses.
type Client interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer is a crypto.Signer whose private key is an AWS KMS key.
type Signer struct {
	client Client
	keyID  string
	pub    *ecdsa.PublicKey
	// Timeout bounds each KMS Sign call (crypto.Signer has no context).
	// New sets it to 30 seconds.
	Timeout time.Duration
}

// New returns a Signer for keyID. It fetches the public key and checks that
// the key can sign ES256.
func New(ctx context.Context, client Client, keyID string) (*Signer, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("awskms: get public key: %w", err)
	}
	if out.KeySpec != types.KeySpecEccNistP256 {
		return nil, fmt.Errorf("awskms: key spec is %s; C2paSeal signs ES256 and needs ECC_NIST_P256", out.KeySpec)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("awskms: key usage is %s, want SIGN_VERIFY", out.KeyUsage)
	}
	if !slices.Contains(out.SigningAlgorithms, types.SigningAlgorithmSpecEcdsaSha256) {
		return nil, fmt.Errorf("awskms: key does not offer ECDSA_SHA_256 (has %v)", out.SigningAlgorithms)
	}
	k, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms: parse public key: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("awskms: public key is %T, want ECDSA P-256", k)
	}
	id := keyID
	if out.KeyId != nil {
		id = *out.KeyId // the key ARN, also for an alias
	}
	return &Signer{client: client, keyID: id, pub: pub, Timeout: 30 * time.Second}, nil
}

// KeyID returns the key's ARN (or the ID it was opened with, if KMS did not
// return one).
func (s *Signer) KeyID() string { return s.keyID }

// Public returns the key's public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign asks KMS to sign a SHA-256 digest and returns the ASN.1 DER
// signature, after checking it against the public key.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// go-cose passes nil opts, as crypto/ecdsa allows; the digest length
	// still has to be SHA-256's.
	if (opts != nil && opts.HashFunc() != crypto.SHA256) || len(digest) != 32 {
		return nil, errors.New("awskms: only SHA-256 digests can be signed (ES256)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: sign: %w", err)
	}
	if !ecdsa.VerifyASN1(s.pub, digest, out.Signature) {
		return nil, errors.New("awskms: KMS returned a signature that does not verify with the key's public key")
	}
	return out.Signature, nil
}

// Provider opens awskms: URIs (see the package documentation). It is
// registered with sign.RegisterKeyProvider when the package is imported.
type Provider struct{}

// Open implements sign.KeyProvider.
func (Provider) Open(ctx context.Context, u *url.URL) (crypto.Signer, error) {
	keyID := u.Opaque
	if keyID == "" { // awskms://alias/name or awskms:///arn:…
		keyID = strings.TrimPrefix(u.Host+u.Path, "/")
	}
	if keyID == "" {
		return nil, errors.New("awskms: URI names no key")
	}
	q := u.Query()
	var opts []func(*config.LoadOptions) error
	region := q.Get("region")
	if region == "" {
		region = arnRegion(keyID)
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if p := q.Get("profile"); p != "" {
		opts = append(opts, config.WithSharedConfigProfile(p))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("awskms: load AWS config: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("awskms: no region: use a key ARN, add ?region=…, or set AWS_REGION")
	}
	client := kms.NewFromConfig(cfg, func(o *kms.Options) {
		if e := q.Get("endpoint"); e != "" {
			o.BaseEndpoint = aws.String(e)
		}
	})
	return New(ctx, client, keyID)
}

// arnRegion returns the region of a KMS ARN
// ("arn:aws:kms:<region>:<account>:key/…"), or "".
func arnRegion(id string) string {
	parts := strings.SplitN(id, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && parts[2] == "kms" {
		return parts[3]
	}
	return ""
}
