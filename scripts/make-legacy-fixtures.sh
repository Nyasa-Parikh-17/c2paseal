#!/usr/bin/env bash
# make-legacy-fixtures.sh — build testdata/legacy/: C2PA 1.x files (claim v1)
# and their oracle output.
#
#   - Files from the public c2pa-rs test corpus (sdk/tests/fixtures), pinned
#     to one commit and checked by SHA-256. c2pa-rs is dual-licensed MIT OR
#     Apache-2.0. Most are signed PS256 by c2pa-rs's own test PKI.
#   - v1*.{jpg,png}: claim v1 written by c2patool with the TEST ONLY ES256
#     PKI in testdata/pki ("claim_version": 1).
#
# Only this directory is regenerated; the rest of the corpus is untouched.
# Needs: c2patool, curl, sha256sum and Go, and network access to GitHub.
# Run from the repo root.
set -euo pipefail
export MSYS_NO_PATHCONV=1

command -v c2patool >/dev/null || { echo "make-legacy-fixtures: c2patool not on PATH" >&2; exit 1; }

abs() {
  local p=$1
  case $p in /* | [A-Za-z]:/*) ;; *) p="$PWD/$p" ;; esac
  if command -v cygpath >/dev/null; then cygpath -m "$p"; else echo "$p"; fi
}

T=testdata
L=$T/legacy
PKI=$T/pki
COMMIT=f67921a6ee069878d15db9ff601bf5babcefdff6
BASE=https://raw.githubusercontent.com/contentauth/c2pa-rs/$COMMIT/sdk/tests/fixtures

WORK=$(abs "$(mktemp -d)")
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/settings.toml"
export C2PATOOL_SETTINGS="$WORK/settings.toml"

rm -rf "$L"
mkdir -p "$L"

# --- c2pa-rs corpus ------------------------------------------------------------
while read -r sum name; do
  curl -sSfL -o "$L/$name" "$BASE/$name"
  echo "$sum  $L/$name" | sha256sum -c --quiet
  echo "fetched: $L/$name"
done <<'LIST'
a2d14755db55de67a47c04090340d8266e892367be4104a45626d7a6fa6e9ffd C.jpg
e71bff58fc57640803e6e65f7534e2fb0c2f99018c85276cc14b30f04427cc76 CA.jpg
e735fe9e50057f8280baf96182a38d516a4acfb144da7f1e6aad32de44c76aea CACA.jpg
81f20702a2e81611b29aa773f811b59ade6095acd3d089d6ffdae6b591d6d5a5 XCA.jpg
20dc072a4c843d3b7d7cb4f4002fbb4d8f20d7ee859ca726f2458c1e0358a98c E-sig-CA.jpg
0c343c0f7c07ff6a1e8a0ec3d69d79fe2990d72450e778702e0fdae6458206c5 CIE-sig-CA.jpg
b3ff3f00c66602280977d3e4d962a836d33ab83953d0009f7c1e6490d0065feb adobe-20220124-E-clm-CAICAI.jpg
e64168ba337fb8793f8577d4a9194f21df4bf0bce7b90485fe4dc46ccf0d2d2d legacy_ingredient_hash.jpg
17ea3035caaa4eb6f7cb06c89bda6c86a74a92c40dc5b8119e9954ed9cd99831 prerelease.jpg
49a6b089bf3fe610960ef91b2beb81c86b62e7d531c97f33fc029841d864b2cb ocsp.jpg
LIST

# --- claim v1 from c2patool, TEST ONLY PKI ----------------------------------------
cat > "$WORK/v1.json" <<JSON
{
  "claim_version": 1,
  "alg": "es256",
  "sign_cert": "$(abs "$PKI/leaf-chain.pem")",
  "private_key": "$(abs "$PKI/leaf.key")",
  "title": "C2paSeal v1 fixture",
  "claim_generator_info": [{"name": "c2paseal-fixtures", "version": "1.0"}]
}
JSON
cat > "$WORK/v1-edited.json" <<JSON
{
  "claim_version": 1,
  "alg": "es256",
  "sign_cert": "$(abs "$PKI/leaf-chain.pem")",
  "private_key": "$(abs "$PKI/leaf.key")",
  "claim_generator_info": [{"name": "c2paseal-fixtures", "version": "1.0"}],
  "assertions": [
    {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.color_adjustments"}]}}
  ]
}
JSON

sign() { # <src> <out> <manifest> [extra c2patool args]
  local src=$1 out=$2 m=$3; shift 3
  c2patool "$(abs "$src")" -m "$m" -o "$(abs "$out")" -f "$@" >/dev/null
  echo "signed: $out"
}
sign "$T/unsigned/small.jpg" "$L/v1.jpg"        "$WORK/v1.json"        --create digitalCapture
sign "$T/unsigned/small.png" "$L/v1.png"        "$WORK/v1.json"        --create digitalCapture
sign "$L/v1.jpg"             "$L/v1-edited.jpg" "$WORK/v1-edited.json" -p "$(abs "$L/v1.jpg")"

# --- oracle ----------------------------------------------------------------------
go run ./scripts/oracle "$T" legacy
