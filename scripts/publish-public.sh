#!/usr/bin/env bash
# Republish the public tree: export (allowlist + secrets gate) -> sync into the
# public clone (keeps its .git) -> commit -> push to github.com/oknek/oknek.
#   scripts/publish-public.sh "docs: fix quickstart"
set -euo pipefail
MSG=${1:-"sync from private main $(git -C "$(dirname "$0")/.." rev-parse --short HEAD)"}
PUB=${OKNEK_PUBLIC:-$HOME/oknek-public}
SRC=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
"$SRC/scripts/export-public.sh" "$TMP/tree"
[ -d "$PUB/.git" ] || { echo "publish-public: $PUB is not a git clone of oknek/oknek" >&2; exit 1; }
rsync -a --delete --exclude='.git' "$TMP/tree/" "$PUB/"
rm -rf "$TMP"
cd "$PUB"
git add -A
if git diff --cached --quiet; then echo "publish-public: nothing to publish"; exit 0; fi
git -c user.name="Oknek" -c user.email="hello@oknek.com" commit -q -m "$MSG"
git push origin main
echo "publish-public: pushed $(git rev-parse --short HEAD)"
