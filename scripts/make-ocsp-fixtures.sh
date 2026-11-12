#!/usr/bin/env bash
# make-ocsp-fixtures.sh — build testdata/ocsp/: small.jpg signed by each
# OCSP test signer (testdata/pki/ocsp, see scripts/genocsppki) with the TEST
# ONLY responder's answer stapled (good, revoked, unknown), and their oracle
# output. c2pa-rs reads stapled responses but does not write them, so these
# files are signed by C2paSeal and checked by c2patool.
#
# Only this directory is regenerated. Re-running scripts/genocsppki makes new
# keys and serials, so run this afterwards.
# Needs: c2patool and Go. Run from the repo root.
set -euo pipefail
export MSYS_NO_PATHCONV=1

command -v c2patool >/dev/null || { echo "make-ocsp-fixtures: c2patool not on PATH" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/settings.toml"
export C2PATOOL_SETTINGS="$WORK/settings.toml"

rm -rf testdata/ocsp
go run ./scripts/make-ocsp-fixtures testdata
go run ./scripts/oracle testdata ocsp
