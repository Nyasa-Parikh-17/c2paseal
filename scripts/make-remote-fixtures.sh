#!/usr/bin/env bash
# make-remote-fixtures.sh — build testdata/remote/: c2patool-signed files
# whose manifest store is kept outside the file, and their oracle output.
#
#   embedded-remote.{jpg,png}  store embedded, and referenced from XMP (-r)
#   sidecar.jpg, sidecar-png.png  store only in <name>.c2pa next to the file (-s)
#   remote.jpg, remote-png.png    store only at the XMP URL (-s -r); the
#                                 stores live in remote/served/ and are served
#                                 on http://127.0.0.1:8765/ while the oracle runs
#
# Only this directory is regenerated; the rest of the corpus is untouched.
# Needs: c2patool and Go. Run from the repo root.
set -euo pipefail
export MSYS_NO_PATHCONV=1

command -v c2patool >/dev/null || { echo "make-remote-fixtures: c2patool not on PATH" >&2; exit 1; }

abs() {
  local p=$1
  case $p in /* | [A-Za-z]:/*) ;; *) p="$PWD/$p" ;; esac
  if command -v cygpath >/dev/null; then cygpath -m "$p"; else echo "$p"; fi
}

T=testdata
R=$T/remote
PKI=$T/pki
PORT=8765
URL=http://127.0.0.1:$PORT

WORK=$(abs "$(mktemp -d)")
: > "$WORK/settings.toml"
export C2PATOOL_SETTINGS="$WORK/settings.toml"
cat > "$WORK/plain.json" <<JSON
{
  "claim_version": 2,
  "alg": "es256",
  "sign_cert": "$(abs "$PKI/leaf-chain.pem")",
  "private_key": "$(abs "$PKI/leaf.key")",
  "claim_generator_info": [{"name": "c2paseal-fixtures", "version": "1.0"}]
}
JSON

rm -rf "$R"
mkdir -p "$R/served"

# The server serves remote/served/ for the whole run: c2patool reads every
# file back after signing, which fetches remote-only stores.
# It exits by itself after 5 minutes, since kill cannot always stop it on
# Windows; wait until it answers (a new binary can take seconds to start).
go build -o "$WORK/servedir" ./scripts/servedir
"$WORK/servedir" "127.0.0.1:$PORT" "$R/served" 300 >/dev/null 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 1 100); do
  curl -s -o /dev/null "$URL/" && break
  sleep 0.2
done
curl -s -o /dev/null "$URL/" || { echo "make-remote-fixtures: local server did not start" >&2; exit 1; }

sign() { # <src> <out> [extra c2patool args]
  local src=$1 out=$2; shift 2
  c2patool "$src" -m "$WORK/plain.json" -o "$out" -f --create digitalCapture "$@" >/dev/null
  echo "signed: $out"
}

sign "$T/unsigned/small.jpg" "$R/embedded-remote.jpg" -r "$URL/embedded-remote.c2pa"
sign "$T/unsigned/small.png" "$R/embedded-remote.png" -r "$URL/embedded-remote-png.c2pa"
sign "$T/unsigned/small.jpg" "$R/sidecar.jpg" -s
sign "$T/unsigned/small.png" "$R/sidecar-png.png" -s
# Remote only: sign straight into served/ (so the read-back can fetch the
# store), then move the image out next to the other fixtures.
sign "$T/unsigned/small.jpg" "$R/served/remote.jpg" -s -r "$URL/remote.c2pa"
sign "$T/unsigned/small.png" "$R/served/remote-png.png" -s -r "$URL/remote-png.c2pa"
mv "$R/served/remote.jpg" "$R/served/remote-png.png" "$R/"

go run ./scripts/oracle "$T" remote
echo "remote fixtures done"
