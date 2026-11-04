#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-version>"
    echo "Example: $0 0.8.0"
    exit 1
fi

NEW_VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Bumping phylax to version ${NEW_VERSION}..."

echo "$NEW_VERSION" > "$REPO_ROOT/VERSION"
echo "  Updated VERSION"

# cyrius.cyml is NOT edited: its [package] version is "${file:VERSION}", so it
# follows the VERSION file. Until 1.2.8 this script sed-replaced that line with
# a literal, which is how 1.2.7 shipped `version = "1.2.7"` -- and from cyrius
# 6.6.20 distlib stamps each dist bundle's `# Version:` from the manifest, so a
# stale literal leaks into dist/. CI now refuses a literal (ci.yml, version job).

sed -i "s/VERSION = str_from(\".*\");/VERSION = str_from(\"${NEW_VERSION}\");/" "$REPO_ROOT/src/types.cyr"
echo "  Updated src/types.cyr"

# Verify
FILE_VERSION=$(cat "$REPO_ROOT/VERSION" | tr -d '[:space:]')
CYML_TEMPLATED=0
grep -qF 'version = "${file:VERSION}"' "$REPO_ROOT/cyrius.cyml" && CYML_TEMPLATED=1
SRC_VERSION=$(grep 'VERSION = str_from' "$REPO_ROOT/src/types.cyr" | sed 's/.*str_from("\(.*\)").*/\1/')

if [ "$FILE_VERSION" != "$NEW_VERSION" ] || [ "$CYML_TEMPLATED" != 1 ] || [ "$SRC_VERSION" != "$NEW_VERSION" ]; then
    echo "ERROR: Version mismatch after bump"
    echo "  VERSION:       $FILE_VERSION"
    echo "  cyrius.cyml:   version is \${file:VERSION}? $([ "$CYML_TEMPLATED" = 1 ] && echo yes || echo NO)"
    echo "  src/types.cyr: $SRC_VERSION"
    exit 1
fi

echo ""
echo "Version bumped to ${NEW_VERSION}"
echo ""
echo "Next steps:"
echo "  cyrius distlib --all          # dist/ bundles carry the version; CI gates on --check"
echo "  add a CHANGELOG.md entry for ${NEW_VERSION}"
echo "  git add VERSION src/types.cyr dist/ CHANGELOG.md"
echo "  git commit -m \"bump to ${NEW_VERSION}\""
echo "  git tag ${NEW_VERSION}"
echo "  git push && git push --tags"
