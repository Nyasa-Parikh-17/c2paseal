# sealsvc

A self-hosted C2PA signing service: send it a JPEG, PNG or WebP file, get it
back with Content Credentials signed by your key. The key can be a PEM file
or a key in AWS KMS or Google Cloud KMS. This is its own Go module, so the
KMS SDKs are not dependencies of the core C2paSeal module.

```sh
docker run --rm ghcr.io/nyasa-parikh-17/c2paseal/sealsvc:v0.4.0 hash-key   # make an API key
docker run -p 127.0.0.1:8080:8080 -v ./config:/config:ro ghcr.io/nyasa-parikh-17/c2paseal/sealsvc:v0.4.0 \
  --cert /config/chain.pem --key awskms:arn:aws:kms:… --api-keys /config/api-keys.txt --trust /config/trust.pem

curl -H "Authorization: Bearer $KEY" --data-binary @photo.jpg -o signed.jpg http://127.0.0.1:8080/v1/sign
```

There is a fuller example in [deploy/sealsvc/compose.yaml](../../deploy/sealsvc/compose.yaml).
To build from source: `cd cmd/sealsvc && CGO_ENABLED=0 go build`.

## API

| Request | Body | Answer |
|---|---|---|
| `POST /v1/sign` | JPEG, PNG or WebP | the signed file (`image/jpeg`, `image/png` or `image/webp`); headers `C2paseal-Active-Manifest`, `C2paseal-Manifests` |
| `POST /v1/verify` | JPEG, PNG or WebP | JSON, as `c2paseal verify --json` (`validation_results`, `validation_state`) |
| `GET /healthz` | | `{"status":"ok","version":"…"}` |
| `GET /metrics` | | Prometheus text format |

- `/v1/sign` query parameters: `title`, `source_type` (an IPTC digital
  source type), and `no_history=1` to replace an existing manifest store
  instead of recording it as the parent ingredient.
- `/v1/sign` and `/v1/verify` need `Authorization: Bearer <API key>`.
- Every answer carries `X-Request-Id`, which is also in the audit log.
- Errors are JSON, `{"error": "…", "request_id": "…"}`:

| Status | Meaning |
|---|---|
| 400 | empty body or bad parameter |
| 401 | no or unknown API key |
| 403 | the key lacks the scope |
| 413 | body over `--max-bytes` |
| 415 | not a JPEG, PNG or WebP file |
| 422 | the file cannot be signed (broken, or options that do not apply to it) |
| 429 | rate limit (`Retry-After`) |
| 502 | the key or time-stamp authority failed (details only in the audit log) |
| 503 | at `--max-concurrent` (`Retry-After`) |

A malformed file sent to `/v1/verify` gets a 200 with `Invalid` and the
reasons, not an error.

## Configuration

| Flag | Env | |
|---|---|---|
| `--cert` | `SEALSVC_CERT` | certificate chain for the key, signer first (required) |
| `--key` | `SEALSVC_KEY` | PEM file or key URI: `file:`, `awskms:`, `gcpkms:` (required) |
| `--api-keys` | `SEALSVC_API_KEYS` | API key file (required) |
| `--addr` | `SEALSVC_ADDR` | listen address, default `:8080` |
| `--trust` | | trust anchors for `/v1/verify`, repeatable |
| `--rate` | | default per-key limit, default `60/min` |
| `--tsa` | | RFC 3161 time-stamp authority URL |
| `--max-bytes` | | largest body, default 32 MiB |
| `--max-concurrent` | | sign/verify requests at once, default 2×CPUs |
| `--audit-log` | | append audit records to a file instead of stderr |
| `--tls-cert`, `--tls-key` | | serve HTTPS directly |

The API key file has one key per line. Make each key with
`sealsvc hash-key`, which prints the key (give it to the client) and its
hash (put that in the file):

```
# name    sha256 of the key                                                 options
ci        3b5d…e9a1                                                         rate=120/min
viewer    9f2c…47d0                                                         scopes=verify
```

`scopes` is `sign`, `verify` or both (the default). `rate` is `<n>/min` or
`<n>/s`, with bursts up to the per-minute rate. To change keys, edit the
file and restart.

## Audit log

Each sign or verify request writes one JSON record with `log/slog`. Here is
a real one from the tests:

```json
{"time":"2026-11-14T17:03:31.45+05:30","level":"INFO","msg":"sign","request_id":"6ce9585919af4f127dcad788","endpoint":"sign","method":"POST","path":"/v1/sign","remote_addr":"127.0.0.1:60322","status":200,"bytes_in":1030,"bytes_out":3293,"duration_ms":0,"api_key":"ci","forwarded_for":"203.0.113.7","user_agent":"audit-test/1","format":"jpeg","input_sha256":"4b70ce9c…adee4","output_sha256":"54955d45…ce838","active_manifest":"urn:c2pa:7ac153e1-848e-4699-a707-cb27058d7611","manifests":1}
```

- Refused requests are `WARN` and server-side failures are `ERROR`, with an
  `error` field.
- At startup a `start` record names the key URI (without its query), the
  signer certificate's subject, SHA-256 and expiry, and the number of API
  keys and trust anchors.
- No record contains an API key, its hash, the `Authorization` header or
  file contents: only the key's name and the files' SHA-256.

## Security notes

- **TLS:** sealsvc serves plain HTTP unless given `--tls-cert`. Put it
  behind a TLS proxy and publish the port only to that proxy (the compose
  example binds 127.0.0.1).
- **API keys:** 32 random bytes from `hash-key`. Only their SHA-256 is
  stored, and lookups compare every stored hash in constant time.
  `/healthz` and `/metrics` need no key; `/metrics` shows key *names* but
  never keys.
- **Signing key:** with `awskms:` or `gcpkms:` the private key never leaves
  KMS. Give sealsvc's identity only `kms:GetPublicKey` and `kms:Sign` (AWS),
  or `viewPublicKey` and `useToSign` (Google), on that one key. At startup
  sealsvc checks that the key matches the certificate. Each signature KMS
  returns is verified before use.
- **Limits:** body size, per-key rate, concurrent requests, and header, read
  and write timeouts, against memory exhaustion and slow clients.
- **Client IP:** the audit log records the connection's address.
  `X-Forwarded-For` is logged as sent, as `forwarded_for`, and is not
  trusted for anything.
- **Container:** a static `CGO_ENABLED=0` binary on distroless, running as
  `nonroot`. It works with `--read-only` and `--cap-drop ALL` (CI runs it
  that way).
- **What a signature means:** sealsvc signs whatever an authorized client
  sends, as the certificate's subject. It records that this key signed this
  file, not where the picture came from. Issue API keys accordingly.
