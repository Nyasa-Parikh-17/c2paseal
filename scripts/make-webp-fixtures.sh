#!/usr/bin/env bash
# make-webp-fixtures.sh — add the WebP fixtures (Phase 26) without touching
# the rest of the corpus.
#
#   testdata/unsigned/*.webp  from the PNG originals, with Pillow (libwebp)
#   testdata/signed/*.webp    signed by c2patool with the TEST ONLY PKI
#   testdata/broken/*.webp    one defect each (scripts/mkbroken)
#   oracle JSON               scripts/oracle, for the new files only
#
# Needs: Python 3 with Pillow built with WebP, c2patool on PATH, Go,
# network access to the TSA (TSA_URL). Run from the repo root.
set -euo pipefail
export MSYS_NO_PATHCONV=1
T=testdata
PKI=$T/pki
TSA_URL=${TSA_URL:-http://timestamp.digicert.com}

command -v c2patool >/dev/null || { echo "make-webp-fixtures: c2patool not on PATH" >&2; exit 1; }

abs() {
  local p=$1
  case $p in /* | [A-Za-z]:/*) ;; *) p="$PWD/$p" ;; esac
  if command -v cygpath >/dev/null; then cygpath -m "$p"; else echo "$p"; fi
}

# --- unsigned ---------------------------------------------------------------
# small.webp  lossless (VP8L), simple format
# lossy.webp  lossy (VP8), simple format
# alpha.webp  lossy with an alpha gradient: extended format (VP8X, ALPH, VP8)
# large.webp  lossy, larger, so the signed manifest carries a bigger thumbnail
python - "$T/unsigned" <<'PY'
import sys, os
from PIL import Image, features
assert features.check("webp"), "Pillow lacks WebP support"
d = sys.argv[1]
small = Image.open(os.path.join(d, "small.png")).convert("RGB")
large = Image.open(os.path.join(d, "large.png")).convert("RGB")
small.save(os.path.join(d, "small.webp"), "WEBP", lossless=True, exact=True, method=6)
small.save(os.path.join(d, "lossy.webp"), "WEBP", quality=80, method=6)
alpha = small.copy()
alpha.putalpha(Image.linear_gradient("L").resize(small.size))
alpha.save(os.path.join(d, "alpha.webp"), "WEBP", quality=80, method=6)
large.save(os.path.join(d, "large.webp"), "WEBP", quality=90, method=6)
PY

# --- signed -----------------------------------------------------------------
WORK=$(abs "$(mktemp -d)")
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/settings.toml"
export C2PATOOL_SETTINGS="$WORK/settings.toml"
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
# small and ts keep c2patool's automatic thumbnail. For the lossy sources
# c2patool's WebP thumbnail is about 300 KB (and stored twice, for the claim
# and the ingredient), so those are signed without one.
sign "$T/unsigned/small.webp" "$T/signed/small.webp" "$WORK/plain.json"
sign "$T/unsigned/small.webp" "$T/signed/ts.webp" "$WORK/ts.json"
printf '[builder.thumbnail]\nenabled = false\n' > "$WORK/nothumb.toml"
for n in lossy alpha large; do
  C2PATOOL_SETTINGS="$WORK/nothumb.toml" sign "$T/unsigned/$n.webp" "$T/signed/$n.webp" "$WORK/plain.json"
done

# --- broken -----------------------------------------------------------------
# (rewrites the existing broken files byte for byte; adds the .webp ones)
go run ./scripts/mkbroken "$T/signed" "$T/broken"

# --- oracle -----------------------------------------------------------------
go run ./scripts/oracle -only '*.webp' "$T" unsigned signed broken
