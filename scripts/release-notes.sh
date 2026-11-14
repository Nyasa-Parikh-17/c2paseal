#!/bin/sh
# Prints the GitHub release notes for a version: its CHANGELOG.md section,
# then how to check that the published archives are reproducible.
#
#   scripts/release-notes.sh <version>      e.g. scripts/release-notes.sh v0.2.0
#
# Run with the same Go as scripts/release.sh, since the notes name it.
set -eu

version=${1:?usage: scripts/release-notes.sh <version>}
section=$(awk -v v="## $version" '
	index($0, v) == 1 { on = 1; next }
	on && /^## / { exit }
	on { print }
' CHANGELOG.md)
if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
	echo "release-notes.sh: no \"## $version\" section in CHANGELOG.md" >&2
	exit 1
fi
gover=$(go env GOVERSION)

printf '%s\n' "$section" | sed '/./,$!d'
cat <<NOTES

### Checking a release

The archives are reproducible: rebuilding them from the tag with the same
Go version gives the same bytes on Linux, macOS or Windows. This release was
built with **$gover**.

\`\`\`sh
git clone https://github.com/Nyasa-Parikh-17/c2paseal && cd c2paseal
git checkout $version
GOTOOLCHAIN=$gover sh scripts/release.sh $version
diff dist/SHA256SUMS SHA256SUMS   # SHA256SUMS downloaded from this release
\`\`\`

No output from \`diff\` means every archive matches. Run it in a clean
checkout: local changes stamp the binaries \`vcs.modified=true\`.
NOTES
