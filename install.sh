#!/bin/sh
# oknek installer — installs oknekd, the oknek CLI and the LD_PRELOAD shim,
# then starts the daemon under systemd. Linux only. Run as root.
#
#   # 1. straight from the latest release (downloads + verifies SHA-256):
#   curl -fsSL https://raw.githubusercontent.com/oknek/oknek/main/install.sh | sudo sh
#
#   # 2. from release assets you already downloaded (any dir, either naming):
#   sudo sh install.sh
#
#   # 3. from a built checkout (make build && make shim-linux):
#   sudo sh install.sh
#
# Env: OKNEK_VERSION (default: latest release tag, e.g. v0.9.0)
#      OKNEK_PREFIX  (default: /usr/local)
#      OKNEK_ARCH    (default: detected; only linux/amd64 ships prebuilt today)
set -eu

PREFIX="${OKNEK_PREFIX:-/usr/local}"
LIBDIR="$PREFIX/lib/oknek"
VERSION="${OKNEK_VERSION:-latest}"
REPO="oknek/oknek"

# When piped from curl, $0 is "sh" / "-" and dirname is meaningless — fall back
# to the working directory so mode 2 still finds assets sitting next to you.
case "${0:-}" in
	-|sh|bash|/dev/fd/*|/proc/self/fd/*) SRCDIR="$(pwd)" ;;
	*)
		# Not `A && B || C` — that runs C when B fails too (shellcheck SC2015).
		if _sd=$(cd "$(dirname "$0")" 2>/dev/null && pwd); then
			SRCDIR="$_sd"
		else
			SRCDIR="$(pwd)"
		fi
		;;
esac

die() { echo "oknek: $*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "Linux only (this is a BPF-LSM daemon); got $(uname -s)"
[ "$(id -u)" = "0" ] || die "please run as root (sudo sh install.sh)"

case "${OKNEK_ARCH:-$(uname -m)}" in
	x86_64|amd64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "unsupported arch $(uname -m) — build from source: make build && make shim-linux" ;;
esac

# ─── locate artifacts locally ──────────────────────────────────────────────
# Accepts both the release naming (oknekd-linux-amd64) and the plain naming
# (oknekd), in the script dir, ./bin and ./dist.
find_local() {
	_base=$1
	for _c in \
		"$SRCDIR/$_base" \
		"$SRCDIR/$_base-linux-$ARCH" \
		"$SRCDIR/bin/$_base" \
		"$SRCDIR/dist/$_base" \
		"$SRCDIR/dist/$_base-linux-$ARCH"
	do
		[ -f "$_c" ] && { printf '%s\n' "$_c"; return 0; }
	done
	return 1
}
find_shim() {
	for _c in \
		"$SRCDIR/liboknek_preload.so" \
		"$SRCDIR/liboknek_preload-linux-$ARCH.so" \
		"$SRCDIR/bin/liboknek_preload.so" \
		"$SRCDIR/dist/liboknek_preload.so"
	do
		[ -f "$_c" ] && { printf '%s\n' "$_c"; return 0; }
	done
	return 1
}
find_unit() {
	for _c in "$SRCDIR/oknekd.service" "$SRCDIR/systemd/oknekd.service"; do
		[ -f "$_c" ] && { printf '%s\n' "$_c"; return 0; }
	done
	return 1
}
find_conf() {
	for _c in "$SRCDIR/oknek.yaml" "$SRCDIR/deploy/oknek.oss.yaml"; do
		[ -f "$_c" ] && { printf '%s\n' "$_c"; return 0; }
	done
	return 1
}

OKNEKD=$(find_local oknekd || true)
OKNEK=$(find_local oknek || true)
SHIM=$(find_shim || true)
UNIT=$(find_unit || true)
CONF=$(find_conf || true)

# ─── remote fallback ───────────────────────────────────────────────────────
# Anything not found locally is fetched from the release (binaries, checksum-
# verified) or from the tagged tree (unit, example config). Each artifact is
# resolved independently: a checkout that has the unit but no binaries, or
# release assets with no unit, both work.
if [ "$VERSION" = "latest" ]; then
	BASE="https://github.com/$REPO/releases/latest/download"
	RAWREF="main"
else
	BASE="https://github.com/$REPO/releases/download/$VERSION"
	RAWREF="$VERSION"
fi

DLDIR=""
# NOTE: must return 0 — in POSIX sh the EXIT trap's status becomes the
# script's exit status, so a bare failing test here would exit 1 on success.
cleanup() { [ -n "$DLDIR" ] && rm -rf "$DLDIR"; return 0; }
trap cleanup EXIT INT TERM
# Sets the global DLDIR. Never call this in a $(...) subshell: the assignment
# would be lost and the temp dir would leak uncleaned.
ensure_dldir() { [ -n "$DLDIR" ] || DLDIR=$(mktemp -d); }

fetch() { # fetch <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
	else
		die "need curl or wget to download artifacts"
	fi
}

if [ -z "$OKNEKD" ] || [ -z "$OKNEK" ] || [ -z "$SHIM" ]; then
	[ "$ARCH" = "amd64" ] || die "no prebuilt linux/$ARCH release yet — build from source: make build && make shim-linux"
	ensure_dldir; D="$DLDIR"
	echo "oknek: downloading $VERSION (linux/$ARCH) from $REPO"
	fetch "$BASE/oknekd-linux-$ARCH"              "$D/oknekd-linux-$ARCH"
	fetch "$BASE/oknek-linux-$ARCH"               "$D/oknek-linux-$ARCH"
	fetch "$BASE/liboknek_preload-linux-$ARCH.so" "$D/liboknek_preload-linux-$ARCH.so"
	fetch "$BASE/SHA256SUMS"                      "$D/SHA256SUMS"

	echo "oknek: verifying SHA-256"
	command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found — refusing to install unverified binaries"
	# Check only the lines for what we downloaded, and require all three to be
	# present: an empty or truncated SHA256SUMS must not silently pass.
	grep -E " (oknekd|oknek|liboknek_preload)-linux-$ARCH(\.so)?\$" "$D/SHA256SUMS" > "$D/.want" \
		|| die "SHA256SUMS has no entries for linux/$ARCH"
	[ "$(wc -l < "$D/.want")" -eq 3 ] || die "SHA256SUMS incomplete for linux/$ARCH (expected 3 entries)"
	( cd "$D" && sha256sum -c .want >/dev/null ) || die "CHECKSUM MISMATCH — refusing to install"

	OKNEKD="$D/oknekd-linux-$ARCH"
	OKNEK="$D/oknek-linux-$ARCH"
	SHIM="$D/liboknek_preload-linux-$ARCH.so"
fi

if [ -z "$UNIT" ]; then
	ensure_dldir; D="$DLDIR"
	echo "oknek: fetching systemd unit ($RAWREF)"
	fetch "https://raw.githubusercontent.com/$REPO/$RAWREF/systemd/oknekd.service" "$D/oknekd.service" \
		|| die "could not fetch systemd/oknekd.service"
	UNIT="$D/oknekd.service"
fi

if [ -z "$CONF" ]; then
	ensure_dldir; D="$DLDIR"
	# Optional: without it the daemon uses its built-in defaults.
	if fetch "https://raw.githubusercontent.com/$REPO/$RAWREF/deploy/oknek.oss.yaml" "$D/oknek.yaml" 2>/dev/null; then
		CONF="$D/oknek.yaml"
	fi
fi

[ -n "$OKNEKD" ] || die "missing artifact: oknekd"
[ -n "$OKNEK" ]  || die "missing artifact: oknek"
[ -n "$SHIM" ]   || die "missing artifact: liboknek_preload.so (make shim-linux)"
[ -n "$UNIT" ]   || die "missing artifact: oknekd.service"

# ─── install ───────────────────────────────────────────────────────────────
echo "oknek: installing binaries to $PREFIX/bin"
mkdir -p "$PREFIX/bin"
install -m 0755 "$OKNEKD" "$PREFIX/bin/oknekd"
install -m 0755 "$OKNEK"  "$PREFIX/bin/oknek"

echo "oknek: installing shim to $LIBDIR"
mkdir -p "$LIBDIR"
install -m 0644 "$SHIM" "$LIBDIR/liboknek_preload.so"

echo "oknek: installing systemd unit"
install -m 0644 "$UNIT" /etc/systemd/system/oknekd.service

# Never clobber an existing config — an upgrade must not silently widen policy.
if [ -n "$CONF" ]; then
	mkdir -p /etc/oknek
	if [ -f /etc/oknek/oknek.yaml ]; then
		echo "oknek: keeping existing /etc/oknek/oknek.yaml (new default written to oknek.yaml.new)"
		install -m 0640 "$CONF" /etc/oknek/oknek.yaml.new
	else
		echo "oknek: installing config to /etc/oknek/oknek.yaml (observe-first defaults)"
		install -m 0640 "$CONF" /etc/oknek/oknek.yaml
	fi
fi

systemctl daemon-reload
systemctl enable --now oknekd

# Give the daemon a moment to bind its socket before we ask it anything.
i=0
while [ $i -lt 10 ]; do
	[ -S /run/oknek/oknek.sock ] && break
	i=$((i + 1)); sleep 1
done

echo "oknek: daemon status —"
"$PREFIX/bin/oknek" status || true

cat <<EOF

oknek installed.
  Prove enforcement:  oknek doctor            # want: KERNEL-ENFORCED, 14/14 links pinned
  Protect an agent:   oknek run --agent claude-code --profile dev -- claude
  Read the audit:     oknek okular  ·  oknek replay <agent>
  Daemon:             systemctl status oknekd

If doctor says DEGRADED, BPF-LSM is not active. Add bpf to GRUB_CMDLINE_LINUX:
  lsm=lockdown,capability,landlock,yama,apparmor,bpf   -> update-grub -> reboot
EOF
