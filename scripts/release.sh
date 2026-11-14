#!/bin/sh
# Builds release archives of the c2paseal CLI for Linux, macOS and Windows
# (amd64 and arm64), all with CGO_ENABLED=0, plus SHA256SUMS.
#
#   scripts/release.sh <version> [outdir]      e.g. scripts/release.sh v0.2.0
#
# Each archive holds the binary, README.md, LICENSE, CHANGELOG.md and the
# TEST ONLY PKI (testdata/pki), so `c2paseal serve` works from the unpacked
# directory. Run from the repository root of a clean checkout. Needs Go, git
# and sha256sum (or shasum).
#
# The build is reproducible: with the same commit and the same Go version
# (`go version`, also printed by `c2paseal version`), it writes the same
# bytes on any OS. Binaries are built with -trimpath (no local paths) and
# -buildvcs=true (the commit and its time, from git); archives are written
# by scripts/archive with sorted entries and every timestamp set to
# SOURCE_DATE_EPOCH, which defaults to the commit time.
set -eu

version=${1:?usage: scripts/release.sh <version> [outdir]}
out=${2:-dist}
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct)}"

if [ -n "$(git status --porcelain)" ]; then
	echo "release.sh: warning: the working tree has changes; the binaries will be stamped vcs.modified=true" >&2
fi

rm -rf "$out"
mkdir -p "$out"
CGO_ENABLED=0 go build -o "$out/.archive" ./scripts/archive
echo "$(go version), SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
for t in $targets; do
	goos=${t%/*}
	goarch=${t#*/}
	name="c2paseal_${version}_${goos}_${goarch}"
	dir="$out/$name"
	mkdir -p "$dir/testdata/pki"
	bin=c2paseal
	[ "$goos" = windows ] && bin=c2paseal.exe
	echo "build $name"
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -buildvcs=true -ldflags "-s -w" -o "$dir/$bin" ./cmd/c2paseal
	cp README.md LICENSE CHANGELOG.md "$dir/"
	cp testdata/pki/README.md testdata/pki/*.pem testdata/pki/*.key "$dir/testdata/pki/"
	ext=tar.gz
	[ "$goos" = windows ] && ext=zip
	"$out/.archive" -mtime "$SOURCE_DATE_EPOCH" -exec "$bin" "$out/$name.$ext" "$dir"
	rm -rf "$dir"
done
rm -f "$out/.archive"

# "<hash>  <name>" on every OS: sha256sum on Windows marks binary mode with
# "*", which would make SHA256SUMS differ from a Linux build of the same
# archives.
cd "$out"
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum c2paseal_*
else
	shasum -a 256 c2paseal_*
fi | sed 's/ [ *]/  /' > SHA256SUMS
cat SHA256SUMS
