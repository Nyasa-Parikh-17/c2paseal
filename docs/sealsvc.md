# Signing service (sealsvc)

`sealsvc` is a small HTTP service: send it an image, get it back signed.
Your applications then need neither the key nor C2paSeal; they make one
HTTP call. It is self-hosted. You run it, and the key stays in your file
or KMS.

```sh
docker run --rm ghcr.io/nyasa-parikh-17/c2paseal/sealsvc:v0.7.0 hash-key     # make an API key
docker run -p 127.0.0.1:8080:8080 -v ./config:/config:ro ghcr.io/nyasa-parikh-17/c2paseal/sealsvc:v0.7.0 \
  --cert /config/chain.pem --key awskms:arn:aws:kms:… --api-keys /config/api-keys.txt

curl -H "Authorization: Bearer $KEY" --data-binary @photo.jpg -o signed.jpg http://127.0.0.1:8080/v1/sign
```

There is a compose example in [deploy/sealsvc](../deploy/sealsvc/compose.yaml).

## API

| Request | |
|---|---|
| `POST /v1/sign` | Body: JPEG, PNG, WebP, HEIC or AVIF. Answer: the signed file. Query: `title`, `source_type`, `no_history=1` |
| `POST /v1/verify` | Body: an image. Answer: JSON as `c2paseal verify --json` |
| `GET /healthz` | Liveness, no key |
| `GET /metrics` | Prometheus metrics, no key |

Errors are JSON with a `request_id`. A broken file sent to `/v1/verify` is
not an error: it gets `Invalid` and the reasons.

## Operating it

- **API keys:** `sealsvc hash-key` makes a key and its SHA-256. Only the
  hash goes in the key file. Each key can have a rate limit (`rate=120/min`)
  and scopes (`sign`, `verify`).
- **Limits:** body size, per-key rate, concurrent requests and timeouts.
- **Audit log:** one JSON record per request with the key's *name*, the
  input and output SHA-256 and the manifest label. It never records keys
  or file contents.
- **Keys:** `--key` takes `file:`, `awskms:` or `gcpkms:`. At startup
  sealsvc checks that the key matches the certificate. Each KMS signature
  is verified before use.
- **Container:** distroless, non-root, works with `--read-only` and
  `--cap-drop ALL`.
- **TLS:** serve it behind a TLS proxy, or give it `--tls-cert` and
  `--tls-key`.

Every flag, status code and security note:
[cmd/sealsvc/README.md](../cmd/sealsvc/README.md).

## sealsvc or the middleware?

| | sealsvc | [Middleware](middleware.md) |
|---|---|---|
| Your app is in | Any language | Go |
| The key lives | In one service | In each app instance |
| Extra moving parts | A service to run | None |

Both sign *as the certificate holder*, whatever they are sent. Issue API
keys to the clients whose files you are willing to vouch for.
