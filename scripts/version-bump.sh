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

sed -i "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" "$REPO_ROOT/cyrius.cyml"
echo "  Updated cyrius.cyml"

sed -i "s/VERSION = str_from(\".*\");/VERSION = str_from(\"${NEW_VERSION}\");/" "$REPO_ROOT/src/types.cyr"
echo "  Updated src/types.cyr"

# Verify
FILE_VERSION=$(cat "$REPO_ROOT/VERSION" | tr -d '[:space:]')
CYML_VERSION=$(grep '^version = ' "$REPO_ROOT/cyrius.cyml" | head -1 | sed 's/version = "\(.*\)"/\1/')
SRC_VERSION=$(grep 'VERSION = str_from' "$REPO_ROOT/src/types.cyr" | sed 's/.*str_from("\(.*\)").*/\1/')

if [ "$FILE_VERSION" != "$NEW_VERSION" ] || [ "$CYML_VERSION" != "$NEW_VERSION" ] || [ "$SRC_VERSION" != "$NEW_VERSION" ]; then
    echo "ERROR: Version mismatch after bump"
    echo "  VERSION:     $FILE_VERSION"
    echo "  cyrius.cyml: $CYML_VERSION"
    echo "  phylax.cyr:  $SRC_VERSION"
    exit 1
fi

echo ""
echo "Version bumped to ${NEW_VERSION}"
echo ""
echo "Next steps:"
echo "  git add VERSION cyrius.cyml src/phylax.cyr"
echo "  git commit -m \"bump to ${NEW_VERSION}\""
echo "  git tag ${NEW_VERSION}"
echo "  git push && git push --tags"
