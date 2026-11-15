# HTTP middleware

The `middleware` package signs images as they are uploaded, before your
handler sees them. It uses only the standard library and the core module.

```go
import (
	"github.com/Nyasa-Parikh-17/c2paseal"
	"github.com/Nyasa-Parikh-17/c2paseal/middleware"
	"github.com/Nyasa-Parikh-17/c2paseal/sign"
)

signer, err := sign.OpenKey(ctx, "awskms:arn:aws:kms:…") // or "file:key.pem"
chain, err := c2paseal.LoadChain("chain.pem")
signUploads, err := middleware.Sign(middleware.Config{
	Options: &sign.Options{Chain: chain, Signer: signer},
})
http.Handle("POST /upload", signUploads(uploadHandler))
```

Your `uploadHandler` doesn't change. `r.FormFile("photo")` now returns the
signed image.

## What gets signed

| Request | Signed |
|---|---|
| `multipart/form-data` | Every file part that is a JPEG, PNG, WebP, HEIC or AVIF (or only `Config.Fields`). Other parts are copied byte for byte |
| `Content-Type: image/*` | The whole body |
| Anything else | Nothing. The request passes through untouched |

The format is decided from the bytes, not the declared content type.
`middleware.Files(r)` tells the handler what happened to each upload:
field, file name, format, whether it was signed, and whether it already had
credentials. Existing credentials are kept as the parent ingredient.

## Options

| `Config` field | |
|---|---|
| `Options` | The signing options: `Chain` and `Signer` are required. Each file gets its own copy |
| `Prepare` | Called for each file before signing, with its copy of the options. Use it to set the title from the file name or the logged-in user |
| `Fields` | Only sign these form fields |
| `MaxBytes` | The request body limit (default 32 MiB). The body is read into memory |
| `RejectUnsupported` | Refuse uploads that are not supported images (415) instead of passing them through |
| `ErrorHandler` | Write your own error responses |

```go
Prepare: func(r *http.Request, f *middleware.File, o *sign.Options) error {
	user := currentUser(r)
	if user == "" {
		return errors.New("not logged in") // 400
	}
	o.Title = f.Filename + ", uploaded by " + user
	return nil
},
```

## Errors

| Status | When |
|---|---|
| 400 | Malformed multipart body, or `Prepare` returned an error |
| 413 | Body over `MaxBytes` |
| 415 | Unsupported upload, with `RejectUnsupported` |
| 422 | The image cannot be signed (corrupt or truncated) |
| 500 | The key, KMS or time-stamp authority failed. The response does not include the details |

The middleware tells "your file is broken" (422) apart from "our key
failed" (500) by watching the signer. A KMS outage is never blamed on the
user's file.

## Think about what the signature says

The middleware signs **as you**, the holder of the certificate, whatever
the user uploads. The credentials then say "this service received this file
and signed it". They do not say the photo is authentic. See
[what C2PA does and does not prove](what-c2pa-proves.md).

A complete example server: [examples/upload-server](../examples/upload-server/main.go).
