# keys/gcpkms

Signs C2PA manifests with an ES256 key held in Google Cloud KMS: C2paSeal
sends KMS the SHA-256 digest to sign, and the private key never leaves KMS.
This is its own Go module, so the Google Cloud SDK is not a dependency of
the core module.

```go
import (
	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	_ "github.com/Nyasa-Parikh-17/c2paseal/keys/gcpkms" // registers gcpkms:
)

signer, err := sign.OpenKey(ctx, "gcpkms:projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
defer signer.(interface{ Close() error }).Close()
chain, err := c2paseal.LoadChain("chain.pem") // the certificate for the KMS key, then intermediates
err = c2paseal.Sign("in.jpg", "out.jpg", &c2paseal.SignOptions{Chain: chain, Signer: signer})
```

- URI: `gcpkms:<key version name>[?endpoint=…]`. An `http://` endpoint, such
  as a local emulator, is called without credentials.
- The key version: algorithm `EC_SIGN_P256_SHA256`.
- IAM: `cloudkms.cryptoKeyVersions.viewPublicKey` (once, when opening) and
  `cloudkms.cryptoKeyVersions.useToSign`.
- Credentials: Application Default Credentials.
- Request and response CRC32C checksums are checked, and each signature is
  verified against the public key.

Your CA issues the certificate for the key version's public key (from
`gcloud kms keys versions get-public-key`). To be trusted by C2PA
validators, the CA must be on the C2PA trust list.

Tests use a fake KMS endpoint. `TestRealKMS` signs with a real key when
`C2PASEAL_GCPKMS_KEY` and Application Default Credentials are set.
