#!/usr/bin/env bash
# e2e_exfil.sh — proves R12 exfil/C2 watch fires on a watched agent's beaconing
# and velocity, and stays quiet on light traffic. Isolated test daemon (own
# socket/db under /tmp); the prod oknekd on the same box is untouched.
#
# R12 aggregates PER AGENT across connects, so each case drives many connects
# from ONE watched process (`oknek run conn ...` = one process tree = one agent
# id). The BPF socket_connect hook fires at the syscall, so closed dest ports are
# fine — no listener needed. Requires egress_jail enabled (observe) so the
# kernel connect stream flows, plus exfil_watch with low thresholds for speed.
#
# Run: sudo OKNEKD=/path/oknekd OKNEK=/path/oknek bash e2e_exfil.sh
set -u
OKNEKD=${OKNEKD:-/tmp/oknekd-r12}
OKNEK=${OKNEK:-/tmp/oknek-r12}
WORK=${WORK:-/tmp/oknek-r12-e2e}
GW_IP=127.0.0.1; GW_PORT=4000
EXT_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
[ -z "$EXT_IP" ] && EXT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
check(){ if echo "$3" | grep -q "$2"; then echo "PASS: $1"; echo "      └ $(echo "$3" | tr '\n' ' ' | sed 's/  */ /g')"; pass=$((pass+1)); else echo "FAIL: $1 — wanted [$2]"; echo "      got: $3"; fail=$((fail+1)); fi; }
DAEMON_PID=""
cleanup(){ [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; sleep 0.4; echo "[cleanup] test daemon stopped; BPF links freed"; }
trap cleanup EXIT

echo "=== R12 exfil/C2-watch e2e ===  external=$EXT_IP  cc=$CC"
[ -x "$OKNEKD" ] || { echo "missing daemon at $OKNEKD"; exit 2; }
[ -x "$OKNEK" ] || { echo "missing cli at $OKNEK"; exit 2; }
[ -n "$CC" ] || { echo "no C compiler"; exit 2; }
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"

# conn <ip> <port> <count> <interval_ms> — makes <count> off-gateway connect
# attempts to ip:port, sleeping interval_ms between. The LSM hook fires on each.
cat > "$WORK/conn.c" <<'EOF'
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
	if (argc < 5) return 2;
	const char *ip = argv[1]; int port = atoi(argv[2]);
	int n = atoi(argv[3]); long ms = atol(argv[4]);
	for (int i = 0; i < n; i++) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a; memset(&a, 0, sizeof a);
		a.sin_family = AF_INET; a.sin_port = htons(port);
		inet_pton(AF_INET, ip, &a.sin_addr);
		connect(s, (struct sockaddr *)&a, sizeof a); /* hook fires regardless */
		close(s);
		if (ms > 0 && i < n - 1) usleep(ms * 1000);
	}
	return 0;
}
EOF
"$CC" -O2 -o "$WORK/conn" "$WORK/conn.c" || { echo "cc failed"; exit 2; }

cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
egress_jail:
  enabled: true
  gateway: { host: "$GW_IP", port: $GW_PORT }
  enforce: false
exfil_watch:
  enabled: true
  beacon_min_count: 3
  beacon_jitter_tolerance: 0.35
  beacon_min_interval_seconds: 0.3
  velocity_window_seconds: 10
  velocity_max_connects: 20
  cooldown_seconds: 60
EOF

"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/daemon.out" 2>&1 & DAEMON_PID=$!
sleep 1.5
grep -E "R11 active|R12 active" "$WORK/daemon.out" | sed 's/^/      /'
check "R12 active in observe mode" "R12 active" "$(cat "$WORK/daemon.out")"

# --- BEACON: one watched process, 5 connects ~0.6s apart to the same dest ---
"$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" "$EXT_IP" 5000 5 600 >/dev/null 2>&1
sleep 1
EX=$("$OKNEK" --config "$WORK/oknek.yaml" exfil 2>&1)
check "BEACON alert recorded (regular cadence to one dest)" "BEACON" "$EX"

# --- VELOCITY: one watched process, 30 rapid connects (> 20 in 10s window) ---
"$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" "$EXT_IP" 6000 30 0 >/dev/null 2>&1
sleep 1
EX2=$("$OKNEK" --config "$WORK/oknek.yaml" exfil 2>&1)
check "VELOCITY alert recorded (burst > threshold)" "VELOCITY" "$EX2"

# --- QUIET: a fresh light agent making 2 occasional connects → no NEW alert ---
before=$("$OKNEK" --config "$WORK/oknek.yaml" exfil 2>&1 | grep -c -E "BEACON|VELOCITY")
"$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" "$EXT_IP" 7000 2 1500 >/dev/null 2>&1
sleep 1
after=$("$OKNEK" --config "$WORK/oknek.yaml" exfil 2>&1 | grep -c -E "BEACON|VELOCITY")
check "QUIET: light traffic raised no new alert (before=$before after=$after)" "OK" "$([ "$after" -le "$before" ] && echo OK || echo "grew $before→$after")"

echo "================ R12 e2e: $pass passed, $fail failed ================"
exit "$fail"
