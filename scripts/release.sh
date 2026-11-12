#!/bin/sh
# Builds release archives of the c2paseal CLI for Linux, macOS and Windows
# (amd64 and arm64), all with CGO_ENABLED=0, plus SHA256SUMS.
#
#   scripts/release.sh <version> [outdir]      e.g. scripts/release.sh v0.1.0
#
# Each archive holds the binary, README.md, LICENSE and the TEST ONLY PKI
# (testdata/pki), so `c2paseal serve` works from the unpacked directory.
# Run from the repository root. Needs Go, tar, zip and sha256sum (or
# shasum).
set -eu

version=${1:?usage: scripts/release.sh <version> [outdir]}
out=${2:-dist}
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

rm -rf "$out"
mkdir -p "$out"
for t in $targets; do
	goos=${t%/*}
	goarch=${t#*/}
	name="c2paseal_${version}_${goos}_${goarch}"
	dir="$out/$name"
	mkdir -p "$dir/testdata/pki"
	bin=c2paseal
	[ "$goos" = windows ] && bin=c2paseal.exe
	echo "build $name"
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags "-s -w" -o "$dir/$bin" ./cmd/c2paseal
	cp README.md LICENSE "$dir/"
	cp testdata/pki/README.md testdata/pki/*.pem testdata/pki/*.key "$dir/testdata/pki/"
	if [ "$goos" = windows ]; then
		(cd "$out" && zip -qr "$name.zip" "$name")
	else
		tar -C "$out" -czf "$out/$name.tar.gz" "$name"
	fi
	rm -rf "$dir"
done

cd "$out"
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum c2paseal_* > SHA256SUMS
else
	shasum -a 256 c2paseal_* > SHA256SUMS
fi
cat SHA256SUMS
