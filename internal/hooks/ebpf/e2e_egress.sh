#!/usr/bin/env bash
# e2e_egress.sh — proves the R11 BPF-LSM egress jail blocks route-around in the
# kernel, INCLUDING from a spawned statically-linked child the LD_PRELOAD shim
# can never inject into. Runs a fully ISOLATED test daemon (its own socket / db /
# agent-pid map under /tmp) so it never disturbs a production oknekd on the same
# box — the jail only acts on PIDs registered here via `oknek run`.
#
# Requires: Linux with `bpf` in the active LSM list, a C compiler with static
# libc, root (BPF-LSM attach is privileged). Run: sudo bash e2e_egress.sh
#
# Binaries (override via env): OKNEKD=/path/to/oknekd  OKNEK=/path/to/oknek
set -u

OKNEKD=${OKNEKD:-/tmp/oknekd-r11}
OKNEK=${OKNEK:-/tmp/oknek-r11}
WORK=${WORK:-/tmp/oknek-r11-e2e}
GW_IP=127.0.0.1
GW_PORT=4000
EXT_PORT=5000
EXT_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
[ -z "$EXT_IP" ] && EXT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
CC=$(command -v cc || command -v gcc || command -v clang)

pass=0
fail=0
check() { # desc  expected_substr  actual
	if echo "$3" | grep -q "$2"; then
		echo "PASS: $1"
		echo "      └ $3"
		pass=$((pass + 1))
	else
		echo "FAIL: $1 — wanted [$2], got [$3]"
		fail=$((fail + 1))
	fi
}

DAEMON_PID=""
GW_PID=""
EXT_PID=""
V6L1=""
V6L2=""
cleanup() {
	[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
	[ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null
	[ -n "$EXT_PID" ] && kill "$EXT_PID" 2>/dev/null
	[ -n "$V6L1" ] && kill "$V6L1" 2>/dev/null
	[ -n "$V6L2" ] && kill "$V6L2" 2>/dev/null
	sleep 0.5
	echo "[cleanup] test daemon + listeners stopped; BPF links freed on exit"
}
trap cleanup EXIT

echo "=== R11 egress-jail e2e ==="
echo "    gateway=$GW_IP:$GW_PORT  external=$EXT_IP:$EXT_PORT  cc=$CC"
[ -x "$OKNEKD" ] || { echo "missing daemon binary at $OKNEKD"; exit 2; }
[ -x "$OKNEK" ] || { echo "missing cli binary at $OKNEK"; exit 2; }
[ -n "$CC" ] || { echo "no C compiler"; exit 2; }

rm -rf "$WORK"
mkdir -p "$WORK/rules/active"

# --- the connect helper: `conn server <ip> <port>` listens; `conn client <ip> <port>` connects ---
cat > "$WORK/conn.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
/* conn server|client <ip> <port> — auto-detects IPv4 vs IPv6 by a ':' in <ip>,
 * so the same helper exercises both the R11 IPv4 and IPv6 egress branches. */
int main(int argc, char **argv) {
	if (argc < 4) { fprintf(stderr, "usage: %s server|client <ip> <port>\n", argv[0]); return 2; }
	int port = atoi(argv[3]);
	int v6 = strchr(argv[2], ':') != NULL;
	int fam = v6 ? AF_INET6 : AF_INET;
	struct sockaddr_storage ss; memset(&ss, 0, sizeof(ss));
	socklen_t slen;
	if (v6) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
		a->sin6_family = AF_INET6; a->sin6_port = htons(port);
		if (inet_pton(AF_INET6, argv[2], &a->sin6_addr) != 1) { fprintf(stderr, "bad ip6\n"); return 2; }
		slen = sizeof(*a);
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;
		a->sin_family = AF_INET; a->sin_port = htons(port);
		if (inet_pton(AF_INET, argv[2], &a->sin_addr) != 1) { fprintf(stderr, "bad ip\n"); return 2; }
		slen = sizeof(*a);
	}
	int s = socket(fam, SOCK_STREAM, 0);
	if (s < 0) { perror("socket"); return 3; }
	if (strcmp(argv[1], "server") == 0) {
		int opt = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		if (bind(s, (struct sockaddr *)&ss, slen) < 0) { perror("bind"); return 4; }
		if (listen(s, 16) < 0) { perror("listen"); return 5; }
		printf("LISTENING %s:%d\n", argv[2], port); fflush(stdout);
		for (;;) { int c = accept(s, 0, 0); if (c >= 0) close(c); }
	} else {
		if (connect(s, (struct sockaddr *)&ss, slen) == 0) { printf("CONNECT_OK\n"); return 0; }
		printf("CONNECT_BLOCKED errno=%d(%s)\n", errno, strerror(errno));
		return 1;
	}
	return 0;
}
EOF
"$CC" -O2 -o "$WORK/conn" "$WORK/conn.c" || { echo "dynamic cc failed"; exit 2; }
STATIC_OK=1
"$CC" -O2 -static -o "$WORK/conn_static" "$WORK/conn.c" 2>/dev/null || STATIC_OK=0
if [ "$STATIC_OK" = 1 ]; then
	# confirm it really is static (the whole point: LD_PRELOAD can't touch it).
	# ldd is reliably present; `file` is not on minimal hosts.
	if ldd "$WORK/conn_static" 2>&1 | grep -qE "not a dynamic executable|statically linked"; then
		echo "[build] conn_static is statically linked (no dynamic libc -> shim-unhookable)"
	else
		STATIC_OK=0
	fi
fi

write_cfg() { # $1 = db file, $2 = enforce (true|false), $3 = block_dns (optional, default false)
	cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/$1
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
egress_jail:
  enabled: true
  gateway: { host: "$GW_IP", port: $GW_PORT }
  block_dns: ${3:-false}
  enforce: $2
EOF
}

start_daemon() { # $1 = out file
	"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/$1" 2>&1 &
	DAEMON_PID=$!
	sleep 1.5
}

# --- listeners (gateway on loopback, "external" on the box's primary IP) ---
"$WORK/conn" server "$GW_IP" "$GW_PORT" >/dev/null 2>&1 & GW_PID=$!
"$WORK/conn" server "$EXT_IP" "$EXT_PORT" >/dev/null 2>&1 & EXT_PID=$!
sleep 0.4

# ===================== PHASE 1: enforce=true =====================
echo ""; echo "--- phase 1: enforce=true ---"
write_cfg oknek.db true
start_daemon daemon1.out
DLOG=$(cat "$WORK/daemon1.out")
echo "$DLOG" | grep -E "eBPF LSM|egress_jail" | sed 's/^/      /'
check "daemon attached BPF-LSM + R11 active (verifier passed at attach)" "egress_jail: R11 active" "$DLOG"

A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client "$GW_IP" "$GW_PORT" 2>&1)
check "watched -> gateway 127.0.0.1:$GW_PORT ALLOWED" "CONNECT_OK" "$A"

B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client "$EXT_IP" "$EXT_PORT" 2>&1)
check "watched -> external $EXT_IP:$EXT_PORT BLOCKED" "CONNECT_BLOCKED" "$B"

if [ "$STATIC_OK" = 1 ]; then
	# `; true` forces sh to fork conn_static (distinct child PID), so this proves
	# the ANCESTRY WALK catches a static child — not just same-pid exec.
	C=$("$OKNEK" --config "$WORK/oknek.yaml" run sh -c "$WORK/conn_static client $EXT_IP $EXT_PORT; true" 2>&1)
	check "watched -> STATIC child external BLOCKED  «HEADLINE: shim can't, kernel does»" "CONNECT_BLOCKED" "$C"
else
	echo "SKIP: static-child test (no static libc on this box)"
fi

D=$("$WORK/conn" client "$EXT_IP" "$EXT_PORT" 2>&1)
check "UNWATCHED -> external ALLOWED (scoping: jail only binds watched trees)" "CONNECT_OK" "$D"

sleep 0.7 # let the ringbuf drain into the store
ST=$("$OKNEK" --config "$WORK/oknek.yaml" status 2>&1)
BLK=$(echo "$ST" | grep -oiE '[0-9]+ blocked' | grep -oE '[0-9]+' | head -1)
[ -z "$BLK" ] && BLK=0
check "R11 block events recorded in store (blocked=$BLK >= 1)" "OK" "$([ "$BLK" -ge 1 ] && echo OK || echo "blocked=$BLK")"

kill "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""; sleep 0.6

# ===================== PHASE 2: enforce=false (observe) =====================
echo ""; echo "--- phase 2: enforce=false (observe-only) ---"
write_cfg oknek2.db false   # fresh db so the blocked counter is unambiguous
start_daemon daemon2.out
DLOG2=$(cat "$WORK/daemon2.out")
echo "$DLOG2" | grep -E "egress_jail" | sed 's/^/      /'

E=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client "$EXT_IP" "$EXT_PORT" 2>&1)
check "observe -> external ALLOWED (enforce=false does not block)" "CONNECT_OK" "$E"

sleep 0.7
ST2=$("$OKNEK" --config "$WORK/oknek.yaml" status 2>&1)
BLK2=$(echo "$ST2" | grep -oiE '[0-9]+ blocked' | grep -oE '[0-9]+' | head -1)
[ -z "$BLK2" ] && BLK2=0
check "observe still LOGS the event (blocked=$BLK2 >= 1, allowed but recorded)" "OK" "$([ "$BLK2" -ge 1 ] && echo OK || echo "blocked=$BLK2")"

kill "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""; sleep 0.6

# ===================== PHASE 3: DNS :53 egress toggle (IPv4) =====================
# The IPv4 branch allows off-gateway :53 egress UNLESS block_dns is set. Proven in
# BOTH directions so the toggle is shown to actually gate (not always-allow). enforce=true
# so a real block surfaces as EPERM (errno 1); an allowed connect reaches the TCP layer
# and — with nothing listening on EXT_IP:53 — returns ECONNREFUSED (errno 111), i.e. NOT
# errno=1. The open-paren in the grep ('errno=1(') distinguishes 1 from 111.
echo ""; echo "--- phase 3: DNS :53 egress toggle (IPv4) ---"
write_cfg oknek3a.db true false   # block_dns=false => DNS allowed (the default)
start_daemon daemon3a.out
F=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client "$EXT_IP" 53 2>&1)
check "DNS :53 ALLOWED through jail when block_dns=false (connect reaches TCP, not EPERM)" "OK" "$(echo "$F" | grep -q 'errno=1(' && echo EPERM-BLOCKED || echo OK)"
echo "      └ $F"
kill "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""; sleep 0.6

write_cfg oknek3b.db true true    # block_dns=true => :53 now jailed
start_daemon daemon3b.out
G=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client "$EXT_IP" 53 2>&1)
check "DNS :53 BLOCKED when block_dns=true (toggle gates: EPERM at the LSM hook)" "errno=1(" "$G"
H=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client "$EXT_IP" "$EXT_PORT" 2>&1)
check "control: non-DNS port stays BLOCKED under block_dns=true" "CONNECT_BLOCKED" "$H"
kill "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""; sleep 0.6

# ===================== PHASE 4: IPv6 egress (v1 allows only ::1 loopback) =====================
# The IPv6 branch in v1 permits ONLY ::1 loopback; every other v6 dest is blocked.
# Tested against the box's own non-loopback global v6 (with a real listener) so an
# allowed connect would crisply succeed — making the EPERM block unambiguous.
echo ""; echo "--- phase 4: IPv6 egress (v1 allows only ::1 loopback) ---"
BOX_V6=$(ip -6 addr show scope global 2>/dev/null | grep -oP 'inet6 \K[0-9a-f:]+' | head -1)
V6PORT=5006
write_cfg oknek4.db true false
start_daemon daemon4.out
cat "$WORK/daemon4.out" | grep -E "egress_jail: R11 active" | sed 's/^/      /'
"$WORK/conn" server ::1 "$V6PORT" >/dev/null 2>&1 & V6L1=$!
if [ -n "$BOX_V6" ]; then "$WORK/conn" server "$BOX_V6" "$V6PORT" >/dev/null 2>&1 & V6L2=$!; fi
sleep 0.4
I=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client ::1 "$V6PORT" 2>&1)
check "IPv6 ::1 loopback ALLOWED (watched -> [::1]:$V6PORT)" "CONNECT_OK" "$I"
if [ -n "$BOX_V6" ]; then
	J=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" client "$BOX_V6" "$V6PORT" 2>&1)
	check "IPv6 non-loopback BLOCKED (watched -> [$BOX_V6]:$V6PORT, EPERM)" "errno=1(" "$J"
	K=$("$WORK/conn" client "$BOX_V6" "$V6PORT" 2>&1)
	check "IPv6 scoping: UNWATCHED -> non-loopback ALLOWED (jail binds only watched trees)" "CONNECT_OK" "$K"
else
	echo "SKIP: IPv6 non-loopback block test (no global IPv6 on this box)"
fi
kill "$V6L1" 2>/dev/null; V6L1=""
[ -n "$V6L2" ] && kill "$V6L2" 2>/dev/null; V6L2=""
kill "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""; sleep 0.6

echo ""
echo "================================================"
echo "  RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "  R11 EGRESS JAIL E2E: ALL PASS" || echo "  R11 EGRESS JAIL E2E: FAILURES"
echo "================================================"
exit "$fail"
