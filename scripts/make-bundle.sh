#!/bin/sh
# Assemble a concierge install bundle: pre-built artifacts + a per-customer
# oknek.yaml with the ingest key stamped in. Does NOT compile — point ARTIFACTS
# at a dir holding: oknekd oknek liboknek_preload.so (produced by `make cross`).
#
#   scripts/make-bundle.sh <ingest_key> <artifacts_dir> <out_dir>
set -eu

KEY="${1:?usage: make-bundle.sh <ingest_key> <artifacts_dir> <out_dir>}"
ARTIFACTS="${2:?missing artifacts_dir}"
OUT="${3:?missing out_dir}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUT"
for f in oknekd oknek liboknek_preload.so; do
	[ -f "$ARTIFACTS/$f" ] || { echo "make-bundle: missing artifact $ARTIFACTS/$f"; exit 1; }
	cp "$ARTIFACTS/$f" "$OUT/$f"
done
cp "$ROOT/systemd/oknekd.service" "$OUT/oknekd.service"
cp "$ROOT/install.sh" "$OUT/install.sh"
sed "s|__OKNEK_INGEST_KEY__|$KEY|" "$ROOT/deploy/oknek.yaml.example" > "$OUT/oknek.yaml"
chmod 0755 "$OUT/install.sh"

echo "bundle ready in $OUT — deliver + run: sudo sh install.sh"
ls -1 "$OUT"
