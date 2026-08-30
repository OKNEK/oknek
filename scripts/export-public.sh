#!/usr/bin/env bash
# Export a clean, publishable tree of oknek into $1 (default ./public-export).
# Allowlist first, then denylist, then a secrets gate that FAILS the export.
# Publishing = run this, then commit the result into github.com/oknek/oknek.
set -euo pipefail
DEST=${1:-public-export}
SRC=$(cd "$(dirname "$0")/.." && pwd)
rm -rf "$DEST"; mkdir -p "$DEST"
rsync -a --prune-empty-dirs \
  --include='cmd/***' --include='internal/***' --include='rules/***' \
  --include='systemd/***' --include='deploy/***' --include='tests/***' \
  --include='scripts/***' --include='docs/' --include='docs/public/***' \
  --include='install.sh' --include='Makefile' --include='go.mod' --include='go.sum' \
  --include='LICENSE' --include='README.md' --include='.gitignore' \
  --exclude='*' "$SRC/" "$DEST/"
# denylist — never ship internal material or built artifacts (the compiled BPF
# object internal/hooks/ebpf/oknek_lsm.o is KEPT: go:embed needs it)
rm -rf "$DEST"/docs/superpowers "$DEST"/results "$DEST"/bundle "$DEST"/dist "$DEST"/bin
find "$DEST" \( -name '*.so' -o -name '*.key' -o -name '*.bak*' -o -name 'victim' -o -name '.DS_Store' \) -delete
# secrets / internal-identity gate
PAT='okik_[A-Za-z0-9]{24,}|sk-ant-|cfut_|AKIA[0-9A-Z]{12}|ghp_[A-Za-z0-9]{20}|5\.78\.[0-9]|178\.156\.[0-9]|82\.25\.[0-9]|5\.161\.[0-9]|thehobby2121|basher-shell'
if grep -rEn "$PAT" "$DEST" --binary-files=without-match --exclude=export-public.sh; then
  echo "export-public: SECRETS GATE FAILED — fix the hits above" >&2; exit 1
fi
# private-key material: a PEM header followed by a real base64 body line. The canary
# package and its tests legitimately contain the header string (decoys), so the
# check is: header present AND a 64-char base64 line in the same file.
while IFS= read -r f; do
  if grep -qE '^[A-Za-z0-9+/]{64}$' "$f"; then
    echo "$f: PEM header + key-shaped body" >&2
    echo "export-public: SECRETS GATE FAILED — private key material" >&2; exit 1
  fi
done < <(grep -rlE 'BEGIN (RSA|OPENSSH|EC) PRIVATE' "$DEST" --binary-files=without-match || true)
echo "export-public: clean tree at $DEST ($(find "$DEST" -type f | wc -l | tr -d ' ') files)"
