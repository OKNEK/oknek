#!/bin/sh
# oknek installer — installs oknekd, the oknek CLI, and the LD_PRELOAD shim,
# then starts the daemon under systemd. Run as root.
#
#   curl -fsSL https://install.oknek.com | sh   (hosted: downloads release artifacts first)
#   sh install.sh                               (local: installs artifacts next to this script)
#
# Expects these files alongside the script (the hosted installer downloads them):
#   oknekd  oknek  liboknek_preload.so  oknekd.service
set -eu

PREFIX="${OKNEK_PREFIX:-/usr/local}"
LIBDIR="$PREFIX/lib/oknek"
SRCDIR="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = "0" ] || { echo "oknek: please run as root (sudo sh install.sh)"; exit 1; }

OKNEKD="$SRCDIR/oknekd"
OKNEK="$SRCDIR/oknek"
SHIM="$SRCDIR/liboknek_preload.so"
UNIT="$SRCDIR/oknekd.service"
for f in "$OKNEKD" "$OKNEK" "$SHIM" "$UNIT"; do
	[ -f "$f" ] || { echo "oknek: missing artifact: $f"; exit 1; }
done

echo "oknek: installing binaries to $PREFIX/bin"
install -m 0755 "$OKNEKD" "$PREFIX/bin/oknekd"
install -m 0755 "$OKNEK"  "$PREFIX/bin/oknek"

echo "oknek: installing shim to $LIBDIR"
mkdir -p "$LIBDIR"
install -m 0644 "$SHIM" "$LIBDIR/liboknek_preload.so"

echo "oknek: installing + starting systemd service"
install -m 0644 "$UNIT" /etc/systemd/system/oknekd.service

if [ -f "$SRCDIR/oknek.yaml" ]; then
	echo "oknek: installing config to /etc/oknek/oknek.yaml"
	mkdir -p /etc/oknek
	install -m 0640 "$SRCDIR/oknek.yaml" /etc/oknek/oknek.yaml
fi

systemctl daemon-reload
systemctl enable --now oknekd

sleep 1
echo "oknek: daemon status —"
"$PREFIX/bin/oknek" status || true

cat <<EOF

oknek installed.
  Protect an agent:  oknek run --agent <name> -- <agent-command>
  Daemon:          systemctl status oknekd
  Live state:      oknek status
EOF
