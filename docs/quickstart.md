# Quickstart

In about five minutes you will sign an image of your own and verify it.
You need a terminal and any JPEG, PNG or WebP picture. You don't need Go.

> **Note:** this uses C2paSeal's TEST ONLY certificate, which comes with
> the download. Its private key is public, so what you sign with it proves
> nothing. It is for trying things out. [Certificates and trust](certificates.md)
> explains what real signing needs.

## 1. Download (1 minute)

Open the [latest release](https://github.com/Nyasa-Parikh-17/c2paseal/releases/latest)
and download the archive for your system:

| System | Archive |
|---|---|
| Windows | `c2paseal_<version>_windows_amd64.zip` (or `_arm64`) |
| macOS, Apple silicon | `c2paseal_<version>_darwin_arm64.tar.gz` |
| macOS, Intel | `c2paseal_<version>_darwin_amd64.tar.gz` |
| Linux | `c2paseal_<version>_linux_amd64.tar.gz` (or `_arm64`) |

Unpack it and open a terminal in the unpacked folder. It holds the
`c2paseal` program and the test certificates in `testdata/pki`.

```sh
tar -xzf c2paseal_*_linux_amd64.tar.gz    # macOS: the darwin archive
cd c2paseal_*_linux_amd64
./c2paseal version
```

On Windows, unzip with Explorer and use PowerShell in the folder: type
`.\c2paseal.exe` wherever this page says `./c2paseal`.

> **macOS:** if the system refuses to open the program, run
> `xattr -d com.apple.quarantine c2paseal` once. The binaries are not
> notarized.

## 2. Sign (1 minute)

Copy a picture into the folder as `photo.jpg` (or `.png`, `.webp`), then:

```sh
./c2paseal sign --cert testdata/pki/leaf-chain.pem --key testdata/pki/leaf.key \
    --in photo.jpg --out signed.jpg --title "My first signed photo"
```

`signed.jpg` looks the same as `photo.jpg`. It now also carries a signed
C2PA manifest: who signed it, when, the actions (here, "created") and a
hash that binds the manifest to the picture.

## 3. Verify (1 minute)

```sh
./c2paseal verify signed.jpg
```

```
active manifest:
  success       claimSignature.insideValidity
  success       claimSignature.validated
  ...
  success       assertion.dataHash.match
                data hash valid
  failure       signingCredential.untrusted
                signing certificate untrusted
state: Valid
```

**Valid** means the credentials are intact and match the file. The signer
is *untrusted* because nothing tells C2paSeal to trust the test
certificate. Tell it to:

```sh
./c2paseal verify --trust testdata/pki/trust-anchors.pem signed.jpg
```

```
active manifest:
  success       signingCredential.trusted
  ...
state: Trusted
```

Now change the file and check again. Any edit breaks the binding:

```sh
./c2paseal sign --cert testdata/pki/leaf-chain.pem --key testdata/pki/leaf.key --in photo.jpg --out tampered.jpg
printf 'x' >> tampered.jpg   # PowerShell: Add-Content tampered.jpg x
./c2paseal verify tampered.jpg
```

The state is now **Invalid**. The signature is still fine, but
`assertion.dataHash.mismatch` says the picture's bytes no longer match what
was signed.

## 4. Look inside (30 seconds)

```sh
./c2paseal inspect signed.jpg
```

This prints the whole manifest store as JSON, in the same shape as the
reference tool's `c2patool --detailed`.

## Next steps

- **From Go:** `go get github.com/Nyasa-Parikh-17/c2paseal`, then follow
  the [Go library](library.md) guide.
- **Real signing:** [Certificates and trust](certificates.md).
- **Check a folder in CI:** the [GitHub Action](github-action.md).
- **In the browser:** drop `signed.jpg` on the
  [web app](https://nyasa-parikh-17.github.io/c2paseal/app/).
