#!/usr/bin/env bash
# Okular proof: every kernel enforcement event is sealed into a hash-chained ledger.
# (1) generate blocked actions -> sealed; (2) `oknek okular` = chain INTACT;
# (3) an attacker edits the log -> `oknek okular` DETECTS the break; (4) `oknek
# replay` reconstructs the agent's timeline. Isolated pins; prod untouched.
set -u
OKNEKD=/tmp/oknekd-okl; OKNEK=/tmp/oknek-okl; WORK=/tmp/oknek-okl-e2e
PINDIR=/sys/fs/bpf/oknek-okltest; CC=$(command -v cc||command -v gcc)
pass=0; fail=0
chk(){ if echo "$3"|grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $(echo "$3"|tr '\n' '~'|sed 's/~/ | /g')"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2]"; echo "$3"|sed 's/^/      /'; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ]&&kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/conn.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){ struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(atoi(v[2])); inet_pton(AF_INET,v[1],&a.sin_addr);
  int s=socket(AF_INET,SOCK_STREAM,0); fcntl(s,F_SETFL,O_NONBLOCK);
  connect(s,(struct sockaddr*)&a,sizeof a); return 0; }
EOF
"$CC" -O2 -o "$WORK/conn" "$WORK/conn.c" || { echo compile-fail; exit 2; }
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
egress_jail: { enabled: true, gateway: { host: "127.0.0.1", port: 4000 }, enforce: true }
okular: { enabled: true }
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "okular active" "okular: tamper-proof audit ledger active" "$(cat "$WORK/out")"

# generate 3 sealed actions (off-gateway connects, all blocked by R11)
for ip in 185.10.20.30 185.10.20.31 185.10.20.32; do
  OKNEK_AGENT=demo-agent "$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" $ip 443 >/dev/null 2>&1
done
sleep 0.6

A=$("$OKNEK" --config "$WORK/oknek.yaml" okular 2>&1)
chk "ledger has entries + chain INTACT" "chain intact" "$A"

echo "--- replay demo-agent ---"
"$OKNEK" --config "$WORK/oknek.yaml" replay demo-agent 2>&1 | head -6

# attacker edits the audit log to hide an action
python3 - "$WORK/okular.db" <<'PY'
import sqlite3,sys
db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE okular_ledger SET payload='{\"dest\":\"scrubbed\"}' WHERE seq=2"); db.commit(); db.close()
print("tampered seq 2")
PY

B=$("$OKNEK" --config "$WORK/oknek.yaml" okular 2>&1)
chk "tamper DETECTED — chain breaks at the edited entry" "TAMPERED.*seq 2|breaks at seq 2" "$B"

echo "===== Okular tamper-proof ledger: $pass passed, $fail failed ====="
exit "$fail"
