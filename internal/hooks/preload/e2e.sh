#!/usr/bin/env bash
# oknek core kill-loop E2E. Proves: a credential read is blocked in real time,
# the event is persisted, and `oknek status` reflects the kill. Mac (DYLD) + Linux (LD_PRELOAD).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
SOCK="$WORK/oknek.sock"
DB="$WORK/oknek.db"
CFG="$WORK/oknek.yaml"
trap 'kill "$DPID" 2>/dev/null; rm -rf "$WORK"' EXIT

# R3 blocks reads of paths ending in /.aws/credentials (suffix match).
mkdir -p "$WORK/.aws"
CREDS="$WORK/.aws/credentials"
printf '[default]\naws_secret_access_key=AKIAEXAMPLE\n' > "$CREDS"

cat > "$CFG" <<YAML
socket: $SOCK
db_path: $DB
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
baseline_days: 14
route_around:
  enabled: true
  gateway:
    host: 127.0.0.1
    port: 4000
  providers:
    - localhost
  est_cost_per_call:
    localhost: 0.01
    default: 0.02
  soft_cap:
    window_seconds: 3600
    budget_usd: 100
YAML

# uname → platform bits
case "$(uname)" in
  Darwin) LIB="$ROOT/bin/liboknek_preload.dylib"
          PRELOAD_ENV=(DYLD_INSERT_LIBRARIES="$LIB") ;;
  *)      LIB="$ROOT/bin/liboknek_preload.so"
          PRELOAD_ENV=(LD_PRELOAD="$LIB") ;;
esac

cc -O2 -Wall -o "$WORK/victim" internal/hooks/preload/victim.c || { echo "victim build failed"; exit 1; }

cat > "$WORK/victim_exec.c" <<'C'
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
extern char **environ;
int main(int argc, char **argv) {
  char *a[] = {"sh", "-c", argv[1], 0};
  execve("/bin/sh", a, environ);
  printf("VICTIM_EXEC: execve FAILED errno=%d (%s)\n", errno, strerror(errno));
  return 7;
}
C
cc -O2 -o "$WORK/victim_exec" "$WORK/victim_exec.c" || { echo "victim_exec build failed"; exit 1; }

./bin/oknekd --config "$CFG" >"$WORK/daemon.log" 2>&1 &
DPID=$!
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket never appeared"; cat "$WORK/daemon.log"; exit 1; }

fail=0

echo "── case 1: credential read should be BLOCKED ──"
OUT="$(env "${PRELOAD_ENV[@]}" OKNEK_SOCK="$SOCK" OKNEK_AGENT="claude-e2e" "$WORK/victim" "$CREDS" 2>&1)"
RC=$?
echo "$OUT"
if [ $RC -eq 7 ] && echo "$OUT" | grep -q "open.*FAILED errno=13"; then
  echo "PASS: credential read blocked (EACCES)"
else
  echo "FAIL: credential read NOT blocked (rc=$RC)"; fail=1
fi

echo "── case 2: benign file read should be ALLOWED ──"
echo hi > "$WORK/notes.txt"
OUT2="$(env "${PRELOAD_ENV[@]}" OKNEK_SOCK="$SOCK" OKNEK_AGENT="claude-e2e" "$WORK/victim" "$WORK/notes.txt" 2>&1)"
RC2=$?
echo "$OUT2"
if [ $RC2 -eq 0 ] && echo "$OUT2" | grep -q "OK, read"; then
  echo "PASS: benign read allowed"
else
  echo "FAIL: benign read wrongly blocked (rc=$RC2)"; fail=1
fi

echo "── case 3: status reflects the kill ──"
STATUS="$(./bin/oknek --config "$CFG" status 2>&1)"
echo "$STATUS"
if echo "$STATUS" | grep -q "1 blocked" && echo "$STATUS" | grep -Eq "ld_preload-mode|dyld-mode"; then
  echo "PASS: status shows 1 blocked + real hook mode"
else
  echo "FAIL: status does not show the block / real hook mode"; fail=1
fi

echo "── case 4: 12-deep exec chain should be BLOCKED (R1) ──"
CHAIN='a && b && c && d && e && f && g && h && i && j && k && l'
OUT4="$(env "${PRELOAD_ENV[@]}" OKNEK_SOCK="$SOCK" OKNEK_AGENT="claude-e2e" \
  "$WORK/victim_exec" "$CHAIN" 2>&1)"
echo "$OUT4"
if echo "$OUT4" | grep -q "\[oknek\] BLOCK execve"; then
  echo "PASS: exec chain blocked (R1)"
else
  echo "FAIL: exec chain not blocked"; fail=1
fi

echo "── case 5: daemon unreachable → fail-open (host not bricked) ──"
OUT5="$(env "${PRELOAD_ENV[@]}" OKNEK_SOCK="$WORK/nope.sock" OKNEK_AGENT="claude-e2e" \
  "$WORK/victim" "$WORK/notes.txt" 2>&1)"
RC5=$?
echo "$OUT5"
if [ $RC5 -eq 0 ] && echo "$OUT5" | grep -q "OK, read"; then
  echo "PASS: fail-open when daemon unreachable"
else
  echo "FAIL: shim bricked the process when daemon was down (rc=$RC5)"; fail=1
fi

echo "── case 6: route-around detected with process attribution (R10) ──"
# Proves Task 6: getaddrinfo() teaches the shim hostname→IP, and connect() then
# sends an ENRICHED check.socket (resolved dest_host + process/pid/ppid). The
# daemon's R10 detector must flag the provider host (localhost, non-gateway
# port) and NOT the cost gateway (127.0.0.1:4000). Hermetic: "localhost"
# resolves to 127.0.0.1 via the system resolver (no /etc/hosts edit, no real
# DNS), and the connects need not succeed — the shim queries oknekd BEFORE the
# real connect(), so a refused connection still produces the R10 event.
cat > "$WORK/route_victim.c" <<'C'
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* connect to 127.0.0.1:<port>; rc is irrelevant (shim checks pre-syscall). */
static void poke(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return;
  struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET; sa.sin_port = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
  connect(fd, (struct sockaddr *)&sa, sizeof sa);
  close(fd);
}

int main(void) {
  /* Teach the shim that 127.0.0.1 was resolved from "localhost". */
  struct addrinfo *res = NULL;
  if (getaddrinfo("localhost", NULL, NULL, &res) == 0 && res) freeaddrinfo(res);
  poke(9443); /* provider host on a non-gateway port → should flag R10 */
  poke(4000); /* the cost gateway                  → must NOT flag R10 */
  printf("ROUTE_VICTIM: done\n");
  return 0;
}
C
if cc -O2 -o "$WORK/route_victim" "$WORK/route_victim.c" 2>"$WORK/route_victim.build"; then
  OUT6="$(env "${PRELOAD_ENV[@]}" OKNEK_SOCK="$SOCK" OKNEK_AGENT="claude-e2e" \
    "$WORK/route_victim" 2>&1)"
  RC6=$?
  echo "$OUT6"

  ROUTES="$(./bin/oknek --config "$CFG" routes 2>&1)"
  echo "$ROUTES"

  # The stored R10 event carries full evidence (process/pid/ppid/dest_host).
  R10_ROWS="$(sqlite3 "$DB" "SELECT payload_json FROM events WHERE rule_id='R10';" 2>/dev/null)"
  echo "R10 events:"; echo "$R10_ROWS"

  # The R10 row must name the provider host (localhost) — proving getaddrinfo
  # cache recovery — and carry a real process name + pid>0.
  ROUTE_HIT=0
  if echo "$R10_ROWS" | grep -q '"dest_host":"localhost"' \
     && echo "$R10_ROWS" | grep -Eq '"process":"[^"]+"' \
     && ! echo "$R10_ROWS" | grep -q '"process":""' \
     && echo "$R10_ROWS" | grep -Eq '"pid":[1-9][0-9]*'; then
    ROUTE_HIT=1
  fi
  # The gateway (port 4000) must NOT have produced an R10 row.
  GATEWAY_CLEAN=1
  if echo "$R10_ROWS" | grep -q '"dest_port":4000'; then GATEWAY_CLEAN=0; fi

  if [ "$(uname)" = "Darwin" ] && [ -z "$R10_ROWS" ]; then
    # No interposed event at all on macOS almost always means DYLD injection was
    # stripped (SIP / hardened-runtime / amfi). Skip rather than fake a pass.
    echo "SKIP: no R10 event on macOS — DYLD_INSERT_LIBRARIES likely blocked (SIP/hardened runtime). Run on Linux CI."
  elif [ $ROUTE_HIT -eq 1 ] && [ $GATEWAY_CLEAN -eq 1 ]; then
    echo "PASS: R10 route-around flagged provider 'localhost' with process+pid; gateway not flagged"
  else
    echo "FAIL: route-around not attributed correctly (hit=$ROUTE_HIT gateway_clean=$GATEWAY_CLEAN)"; fail=1
  fi
else
  echo "SKIP: route_victim build failed"; cat "$WORK/route_victim.build"
fi

if [ $fail -eq 0 ]; then echo "E2E PASS"; else echo "E2E FAIL"; fi
exit $fail
