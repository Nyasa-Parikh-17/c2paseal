# Keys and KMS

C2paSeal signs with any `crypto.Signer` for an ECDSA P-256 key (ES256).
You can name the key with a **URI** through `sign.OpenKey`. The same code
then works with a file in development and a KMS key in production.

```go
signer, err := sign.OpenKey(ctx, keyURI)
chain, err := c2paseal.LoadChain("chain.pem") // the certificate for this key, then intermediates
err = c2paseal.Sign("in.jpg", "out.jpg", &c2paseal.SignOptions{Chain: chain, Signer: signer})
```

| URI | Where the key is | Needs |
|---|---|---|
| `key.pem`, `file:key.pem` | A PEM file (PKCS #8, SEC 1) | Built in |
| `awskms:arn:aws:kms:…:key/…` | AWS KMS. The private key never leaves KMS | `import _ "github.com/Nyasa-Parikh-17/c2paseal/keys/awskms"` |
| `gcpkms:projects/…/cryptoKeyVersions/1` | Google Cloud KMS | `import _ "github.com/Nyasa-Parikh-17/c2paseal/keys/gcpkms"` |

The KMS providers are **separate Go modules**, so the cloud SDKs are never
dependencies of the core module. Importing one registers its URI scheme.

## AWS KMS

- Key: asymmetric, key spec `ECC_NIST_P256`, usage `SIGN_VERIFY`.
- IAM: `kms:GetPublicKey` (once, when opening) and `kms:Sign`.
- URI: `awskms:<key ARN | key ID | alias/name | alias ARN>[?region=…][&profile=…][&endpoint=…]`.
- Credentials and region come from the AWS SDK's default chain.

Details: [keys/awskms](../keys/awskms/README.md).

## Google Cloud KMS

- Key version: algorithm `EC_SIGN_P256_SHA256`.
- IAM: `cloudkms.cryptoKeyVersions.viewPublicKey` and `cloudkms.cryptoKeyVersions.useToSign`.
- URI: `gcpkms:<key version name>[?endpoint=…]`.
- Credentials: Application Default Credentials. Request and response
  CRC32C checksums are checked, and each signature is verified.

Details: [keys/gcpkms](../keys/gcpkms/README.md).

## The certificate

The key is half of it. Your CA issues a certificate for the key's public
key (`aws kms get-public-key`, or `gcloud kms keys versions
get-public-key`). Validators trust the signature only if that CA is on
their trust list. See [Certificates and trust](certificates.md).

## Your own key store

Implement `sign.KeyProvider` and register it:

```go
type vaultProvider struct{}

func (vaultProvider) Open(ctx context.Context, u *url.URL) (crypto.Signer, error) {
	// u is "vault:..."; return a crypto.Signer for an ECDSA P-256 key
}

func init() { sign.RegisterKeyProvider("vault", vaultProvider{}) }
```

The `sign/signtest` package checks a provider end to end. It issues a test
certificate for your key, signs a JPEG and a PNG, and verifies them in
C2paSeal and, if installed, in c2patool.

## What is not supported

- **PKCS #11 hardware security modules.** The Go bindings need CGO, which
  this project does not use. A `crypto.Signer` from another source still
  works.
- **Signing algorithms other than ES256.** Verification also accepts
  ES384, ES512, PS256–PS512 and Ed25519.
