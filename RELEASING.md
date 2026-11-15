# Releasing

How to cut a C2paSeal release. Releases are tagged by the maintainer; the
`release` workflow builds, tests and publishes everything from the tag.

## Modules

The repository has several Go modules. Each module other than the core
requires the core (and some require each other) at a real version, with a
`replace` to the local copy for development:

| Module | Requires | Tagged |
|---|---|---|
| `.` (core) | — | `vX.Y.Z` |
| `keys/awskms`, `keys/gcpkms` | core | `keys/awskms/vX.Y.Z`, `keys/gcpkms/vX.Y.Z` |
| `cmd/sealsvc` | core, keys/awskms, keys/gcpkms | `cmd/sealsvc/vX.Y.Z` |
| `watermark` | — | `watermark/vX.Y.Z` |
| `cmd/sealstore` | core, watermark | `cmd/sealstore/vX.Y.Z` |
| `cmd/c2paseal-wasm` | core, watermark | `cmd/c2paseal-wasm/vX.Y.Z` |
| `examples` | core, watermark | not tagged (copied, not imported) |

## 1. Before

- CI is green on `main` for the commit you will release.
- The phase's human gate is approved.

## 2. The release commit

1. In `CHANGELOG.md`, rename `## Unreleased` to `## vX.Y.Z — YYYY-MM-DD`.
2. In every module's `go.mod`, set the requires on C2paSeal modules to
   `vX.Y.Z` (the table above).
3. Update version numbers in the docs that name one: `docs/github-action.md`
   (`uses: …@vX.Y.Z`) and `docs/sealsvc.md` (the image tag).
4. Check that every module is tidy **in a clean clone** (`go mod tidy` in
   a OneDrive-synced folder fails on placeholder files):

   ```sh
   git clone . /tmp/rel && cd /tmp/rel   # with the release changes applied
   for m in keys/awskms keys/gcpkms cmd/sealsvc cmd/sealstore cmd/c2paseal-wasm watermark examples; do
     (cd $m && go mod tidy && go test ./...)
   done
   git status --short   # must show only the files you changed
   ```

5. Commit as `release vX.Y.Z`.

## 3. Tags

All tags go on the release commit:

```sh
git tag -a vX.Y.Z -m "C2paSeal vX.Y.Z"
for m in keys/awskms keys/gcpkms cmd/sealsvc cmd/sealstore cmd/c2paseal-wasm watermark; do
  git tag -a "$m/vX.Y.Z" -m "$m vX.Y.Z"
done
```

## 4. Push: the main tag on its own

**GitHub creates no workflow events when more than three tags are pushed
at once.** A push of all seven tags together starts no `release` run.
(v0.5.0 and v0.6.0 were first pushed that way, and their release runs had
to be restarted.) So:

```sh
git push origin main
git push origin vX.Y.Z                       # alone: starts the release workflow
git push origin keys/awskms/vX.Y.Z keys/gcpkms/vX.Y.Z cmd/sealsvc/vX.Y.Z
git push origin cmd/sealstore/vX.Y.Z cmd/c2paseal-wasm/vX.Y.Z watermark/vX.Y.Z
```

The module tags need no workflow. They make the modules resolvable with
`go get`.

## 5. After

- The `release` run for `vX.Y.Z` is green: tests on Linux, macOS and
  Windows; archives and `SHA256SUMS`; the smoke test of each archive; the
  GitHub release; the `sealsvc` and `sealstore` images on GHCR.
- The release notes list the Go version and the commands to reproduce the
  archives.
- `go list -m github.com/Nyasa-Parikh-17/c2paseal@vX.Y.Z` resolves (the
  module proxy may take a few minutes).

## If the release workflow did not start

Push the main tag again, alone. A tag that already exists on GitHub must be
deleted there first. Deleting and re-pushing the same tag on the same commit
is safe: the module proxy has the same content.

```sh
git push origin :refs/tags/vX.Y.Z
git push origin vX.Y.Z
```
