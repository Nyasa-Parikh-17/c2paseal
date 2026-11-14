#!/usr/bin/env bash
# make-bmff-fixtures.sh — add the HEIC and AVIF fixtures (Phase 27) without
# touching the rest of the corpus.
#
#   testdata/unsigned/sample.{heic,avif}  from the public c2pa-rs test corpus
#       (sdk/tests/fixtures/sample1.heif and sample1.avif at the commit of tag
#       c2pa-v0.90.21, checked by SHA-256). c2pa-rs is dual-licensed MIT OR
#       Apache-2.0. sample1.heif is HEVC-coded (brands mif1, heic).
#   testdata/signed/*.{heic,avif}         signed by c2patool, TEST ONLY PKI
#   testdata/broken/*.{heic,avif}         one defect each (scripts/mkbroken)
#   oracle JSON                           for the new files only
#
# Needs: c2patool, curl, sha256sum, Go, network access to GitHub and the TSA.
# Run from the repo root.
set -euo pipefail
export MSYS_NO_PATHCONV=1
T=testdata
PKI=$T/pki
TSA_URL=${TSA_URL:-http://timestamp.digicert.com}
COMMIT=712f03b72cbc1b00fc41adee5835fc92be2758d1
BASE=https://raw.githubusercontent.com/contentauth/c2pa-rs/$COMMIT/sdk/tests/fixtures

command -v c2patool >/dev/null || { echo "make-bmff-fixtures: c2patool not on PATH" >&2; exit 1; }

abs() {
  local p=$1
  case $p in /* | [A-Za-z]:/*) ;; *) p="$PWD/$p" ;; esac
  if command -v cygpath >/dev/null; then cygpath -m "$p"; else echo "$p"; fi
}

WORK=$(abs "$(mktemp -d)")
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/settings.toml"
export C2PATOOL_SETTINGS="$WORK/settings.toml"

# --- unsigned -------------------------------------------------------------------
while read -r sum src dst; do
  curl -fsSL -o "$T/unsigned/$dst" "$BASE/$src"
  echo "$sum  $T/unsigned/$dst" | sha256sum -c --quiet -
done <<'LIST'
a10de8204aee73ba1786daca6390546bd7aa6b069aaa644012219a1c11246a43 sample1.avif sample.avif
00d9e0636b645036f77b3809fcd26a29df71b9ee66f2865fd8729b894aeabf59 sample1.heif sample.heic
LIST

# --- signed ---------------------------------------------------------------------
manifest() {
  cat > "$1" <<JSON
{
  "claim_version": 2,
  "alg": "es256",
  "sign_cert": "$(abs "$PKI/leaf-chain.pem")",
  "private_key": "$(abs "$PKI/leaf.key")",
  $2
  "claim_generator_info": [{"name": "c2paseal-fixtures", "version": "1.0"}]
}
JSON
}
manifest "$WORK/plain.json" ""
manifest "$WORK/ts.json" "\"ta_url\": \"$TSA_URL\","
sign() { c2patool "$(abs "$1")" -m "$3" -o "$(abs "$2")" -f >/dev/null; }
sign "$T/unsigned/sample.heic" "$T/signed/sample.heic" "$WORK/plain.json"
sign "$T/unsigned/sample.avif" "$T/signed/sample.avif" "$WORK/plain.json"
sign "$T/unsigned/sample.avif" "$T/signed/ts.avif" "$WORK/ts.json"

# --- broken ---------------------------------------------------------------------
# (rewrites the existing broken files byte for byte; adds the new ones)
go run ./scripts/mkbroken "$T/signed" "$T/broken"

# --- oracle ---------------------------------------------------------------------
go run ./scripts/oracle -only '*.heic' "$T" unsigned signed broken
go run ./scripts/oracle -only '*.avif' "$T" unsigned signed broken
