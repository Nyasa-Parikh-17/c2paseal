# Go library

```sh
go get github.com/Nyasa-Parikh-17/c2paseal
```

The API reference is on
[pkg.go.dev](https://pkg.go.dev/github.com/Nyasa-Parikh-17/c2paseal). This
page covers the common tasks.

## Sign

```go
chain, key, err := c2paseal.LoadSigner("chain.pem", "key.pem")
if err != nil {
	return err
}
err = c2paseal.Sign("in.jpg", "out.jpg", &c2paseal.SignOptions{
	Chain:  chain,
	Signer: key,
	Title:  "Harbour at dawn",
})
```

- `c2paseal.SignBytes(b, opts)` does the same in memory.
- `c2paseal.SignAsset` also returns the manifest store, which you need
  with `Sidecar` or `RemoteURL`.
- `SignOptions.Signer` is any `crypto.Signer` for an ECDSA P-256 key: a
  file, a [KMS key](keys.md), or your own.

Useful options (all in `sign.Options`):

| Option | |
|---|---|
| `Title` | `dc:title` of the claim |
| `Actions`, `DigitalSourceType` | The `c2pa.actions.v2` assertion. By default one `c2pa.created` action (digital capture), or `c2pa.opened` when re-signing |
| `TSAURL` | RFC 3161 time-stamp |
| `FetchOCSP`, `OCSPResponse` | Staple the signer's revocation status |
| `Thumbnail` | A claim thumbnail you provide |
| `SoftBindings` | A `c2pa.soft-binding` assertion, such as a [watermark](watermark.md) ID |
| `NoHistory` | Replace existing credentials instead of recording them as the parent |
| `Sidecar`, `RemoteURL` | Keep the store outside the file |

## Verify

```go
anchors, err := c2paseal.LoadTrustAnchors("C2PA-TRUST-LIST.pem")
if err != nil {
	return err
}
res := c2paseal.VerifyFile("photo.jpg", &c2paseal.VerifyOptions{TrustAnchors: anchors})
switch res.State() {
case verify.Trusted: // intact, and the signer is on your trust list
case verify.Valid:   // intact, signer not trusted
case verify.Invalid: // missing, changed or broken
}
for _, s := range res.Statuses() {
	fmt.Println(s.Kind(), s.Code, s.Explanation)
}
```

`VerifyBytes` works on memory. Verification never returns a Go error for
a bad file: malformed input becomes failure codes such as
`claim.missing` or `assertion.dataHash.mismatch`.

## Read without verifying

```go
ms, err := c2paseal.Read("photo.jpg")
if err != nil {
	return err // no credentials, or unreadable
}
fmt.Println(ms.Active.Label, ms.Active.Claim.Title)
for _, a := range ms.Active.Assertions {
	fmt.Println(a.Label)
}
out, _ := json.MarshalIndent(ms, "", "  ") // the shape of c2patool --detailed
```

## Without files

`ParseSigner`, `ParseTrustAnchors`, `ParseAllowedList` and
`ParseTrustConfig` take bytes instead of paths. Use them for keys from a
secret store or for embedded trust lists.

## Packages

| Package | |
|---|---|
| `c2paseal` | Read, Verify, Sign: the entry points |
| `sign` | Building and signing manifests; key providers (`OpenKey`, `RegisterKeyProvider`) |
| `verify` | Status codes, states, trust options |
| `manifest`, `manifest/assertion`, `manifest/cose` | The decoded data model |
| `container/jpeg`, `container/png`, `container/webp`, `container/bmff`, `container/jumbf` | Byte-exact container readers and writers |
| `middleware` | [HTTP middleware](middleware.md) that signs uploads |

Runnable examples: `go doc -ex github.com/Nyasa-Parikh-17/c2paseal`, and
the [examples](../examples) folder.
