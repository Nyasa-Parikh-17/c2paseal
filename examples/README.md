# C2paSeal examples

Small programs to copy from. Each one is a single `main.go` with a test.

| Example | What it shows |
|---|---|
| [sign-and-verify](sign-and-verify) | The smallest program: sign an image, verify the result |
| [upload-server](upload-server) | A photo upload service that signs every upload, using the HTTP middleware; KMS keys through key URIs |
| [verify-folder](verify-folder) | Check every image in a folder against a trust list, as a CI gate |
| [watermark-recover](watermark-recover) | Watermark and sign a photo, strip and re-encode a copy, then recover its credentials |

## Run them

From this folder, with the TEST ONLY certificates in `../testdata/pki`:

```sh
PKI=../testdata/pki
go run ./sign-and-verify --cert $PKI/leaf-chain.pem --key $PKI/leaf.key \
    --trust $PKI/trust-anchors.pem ../testdata/unsigned/small.jpg

go run ./upload-server --cert $PKI/leaf-chain.pem --key $PKI/leaf.key
curl -F photo=@../testdata/unsigned/small.png http://127.0.0.1:8080/upload

go run ./verify-folder --trust $PKI/trust-anchors.pem ../testdata/signed

go run ./watermark-recover --cert $PKI/leaf-chain.pem --key $PKI/leaf.key \
    ../watermark/testdata/earth_apollo17.jpg
```

The TEST ONLY private keys are public, so files signed with them prove
nothing. For real use you need a certificate from a CA on the C2PA trust list.

## Use them outside this repository

This folder is a Go module of its own. To start a project from it, copy the
folder and delete the `replace` block from `go.mod`. It then builds against
the released modules it requires. The tests skip themselves when the
repository's `testdata` is not there.

`watermark-recover` needs the watermark module, which depends on
`golang.org/x/image`. The other three use only the core module.
