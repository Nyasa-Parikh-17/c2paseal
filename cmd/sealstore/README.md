# sealstore

A self-hosted manifest store. It keeps C2PA manifest stores by watermark
ID, so that a copy of an image whose Content Credentials were stripped can
get them back. This is its own Go module: it uses the [watermark](../../watermark)
module, and the core C2paSeal module does not depend on it.

```sh
# 1. Run the store (API keys as made by `sealsvc hash-key`: "<name> <sha256 hex>" per line)
sealstore serve --dir ./stores --api-keys keys.txt --addr :8090

# 2. Watermark, sign and upload in one step (JPEG or PNG)
sealstore sign --cert chain.pem --key key.pem --in photo.jpg --out photo.signed.jpg \
  --store https://store.example.com --api-key "$KEY"

# 3. Later, for a copy without credentials (JPEG, PNG or WebP)
sealstore recover --store https://store.example.com --trust c2pa-trust-list.pem copy.jpg
```

What `recover` reports for a copy that was re-encoded:

```
watermark: 44b50a3b5e3da757 (confidence 0.73)
recovered: manifest urn:c2pa:… from https://store.example.com
signed by C2paSeal Test Signer (certificate issued by C2paSeal TEST ONLY) at an unknown time (no time-stamp); the signature is valid
the signer is on your trust list
this copy is not the signed file: its bytes changed since signing (re-encoded, resized or edited), so only the watermark links it to these credentials
```

A recovered copy never verifies as unchanged. Its bytes are not the
signed file's, so the hard binding fails, and the report says so. Recovery
succeeds when all of these hold:

- the watermark is read;
- the store has a manifest whose `c2pa.soft-binding` records that ID;
- the claim signature validates;
- nothing else fails, except the hard binding and, without trust anchors,
  the trust check.

The web app's "Recover credentials" tab does the same in the browser.

## API

| Request | | |
|---|---|---|
| `PUT /v1/manifests/{id}` | `Authorization: Bearer <API key>`; body: the manifest store | 201 created, 200 replaced; 422 if its active manifest does not record `{id}` as its watermark soft binding |
| `GET /v1/manifests/{id}` | public, `Access-Control-Allow-Origin: *` | the store (`application/c2pa`), or 404 |
| `GET /healthz` | | `{"status":"ok"}` |

`{id}` is the watermark ID: 16 hex digits, random per image.

## Notes

- **Storage:** one file per ID, `<dir>/<id>.c2pa`, written atomically. Back
  it up by copying the directory.
- **Lookups are public:** anyone holding a copy can read its watermark ID,
  and a manifest store holds nothing that the signed file did not already
  carry. Writes need an API key; only the keys' SHA-256 hashes are stored,
  compared in constant time.
- **Audit log:** JSON via `log/slog` (`--audit-log`), with the key name,
  watermark ID and status of each request; never keys.
- **Container:** `cmd/sealstore/Dockerfile`, distroless and non-root. The
  release workflow publishes it next to sealsvc.
- **Not supported:** the C2PA Soft Binding Resolution API (Future work);
  fingerprint matching, since lookups are by exact watermark ID.
