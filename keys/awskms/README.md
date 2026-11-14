# keys/awskms

Signs C2PA manifests with an ES256 key held in AWS KMS: C2paSeal sends KMS
the SHA-256 digest to sign, and the private key never leaves KMS. This is
its own Go module, so the AWS SDK is not a dependency of the core module.

```go
import (
	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
	_ "github.com/Nyasa-Parikh-17/c2paseal/keys/awskms" // registers awskms:
)

signer, err := sign.OpenKey(ctx, "awskms:arn:aws:kms:eu-west-1:111122223333:key/1234abcd-…")
chain, err := c2paseal.LoadChain("chain.pem") // the certificate for the KMS key, then intermediates
err = c2paseal.Sign("in.jpg", "out.jpg", &c2paseal.SignOptions{Chain: chain, Signer: signer})
```

- URI: `awskms:<key ARN | key ID | alias/name | alias ARN>[?region=…][&profile=…][&endpoint=…]`.
- The key: asymmetric, key spec `ECC_NIST_P256`, key usage `SIGN_VERIFY`.
- IAM: `kms:GetPublicKey` (once, when opening) and `kms:Sign`.
- Credentials and region: the AWS SDK's default chain. The region also
  comes from a key ARN or `?region=`.

Your CA issues the certificate for the KMS key's public key (from
`aws kms get-public-key`). To be trusted by C2PA validators, the CA must
be on the C2PA trust list.

Tests use a fake KMS endpoint. `TestRealKMS` signs with a real key when
`C2PASEAL_AWSKMS_KEY` and AWS credentials are set.
