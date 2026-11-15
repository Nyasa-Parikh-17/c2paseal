# GitHub Action

The C2paSeal action signs images or checks their Content Credentials in a
workflow. It runs on Linux, macOS and Windows runners. It builds C2paSeal
from the tagged source, so it pins exactly the version you name.

## Verify images on every pull request

```yaml
name: content credentials
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: Nyasa-Parikh-17/c2paseal@v0.7.0
        with:
          command: verify
          files: |
            assets/**/*.jpg
            assets/**/*.png
          trust: .github/c2pa-trust-list.pem
          fail-on: untrusted
```

The step fails if any image has missing or broken credentials. With
`fail-on: untrusted` it also fails if the signer is not on your trust list.
Each failure is annotated on the file, and the job summary shows a table of
every file and its state.

## Sign release assets

```yaml
      - uses: Nyasa-Parikh-17/c2paseal@v0.7.0
        id: sign
        with:
          command: sign
          files: dist/images
          cert-pem: ${{ secrets.C2PA_CERT_CHAIN }}
          key-pem: ${{ secrets.C2PA_PRIVATE_KEY }}
          title: Release ${{ github.ref_name }}
          tsa: ${{ vars.TSA_URL }}   # your RFC 3161 time-stamp authority
      - run: echo "${{ steps.sign.outputs.signed-files }}"
```

Signed copies go to `c2paseal-signed/` under their relative paths. Set
`in-place: true` to overwrite the originals instead.

## Inputs

| Input | For | |
|---|---|---|
| `command` | both | `sign` or `verify` (required) |
| `files` | both | One per line: files, folders (their images, recursively) or globs. `**` matches any number of folders (required) |
| `cert` / `cert-pem` | sign | The certificate chain: a file, or its PEM text from a secret |
| `key` / `key-pem` | sign | The private key: a file or `file:` URI, or its PEM text from a secret |
| `out-dir` | sign | Where signed copies go (default `c2paseal-signed`) |
| `in-place` | sign | `true` to overwrite the files |
| `title`, `source-type`, `tsa` | sign | As in the [CLI](cli.md#sign) |
| `no-history` | sign | `true` to replace existing credentials instead of keeping them as the parent |
| `trust` | verify | PEM trust anchor files, one per line |
| `fail-on` | verify | `invalid` (default), `untrusted` or `never` |

## Outputs

| Output | |
|---|---|
| `report` | Path to a JSON Lines report, one line per file (`file`, `state`, `failures`, or `output` for sign) |
| `signed-files` | The signed files, one per line |
| `signed-count`, `trusted-count`, `valid-count`, `invalid-count` | Counts |

## Keys and secrets

- Store the key as an encrypted secret and pass it with `key-pem`. It is
  read from the environment and never written to the workspace.
- A key in AWS or Google Cloud KMS needs a program that imports the
  provider. Use the [Go library](keys.md) or [sealsvc](sealsvc.md) from a
  `run:` step.
- The action installs Go (the version in C2paSeal's `go.mod`) with
  `actions/setup-go` and builds C2paSeal in each job that uses it, so
  nothing prebuilt is downloaded.
