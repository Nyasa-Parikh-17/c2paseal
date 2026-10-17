# C2paSeal

A pure-Go (CGO-free) library and CLI for reading, verifying and **signing**
[C2PA](https://c2pa.org) Content Credentials in JPEG and PNG files.

Pure-Go C2PA readers already exist; C2paSeal adds a signer that does not
need CGO or the Rust toolchain.

**Status:** early development. See [PHASES.md](PHASES.md) for the plan and
[PROGRESS.md](PROGRESS.md) for what is done. Target spec revision and scope:
[SPEC.md](SPEC.md).

```
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
```

Licensed under the [Apache License 2.0](LICENSE).
