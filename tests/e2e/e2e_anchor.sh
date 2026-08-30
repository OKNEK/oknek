#!/usr/bin/env bash
# Okular anchoring: signed, chained head-hash checkpoints. The killer demo — an
# attacker rewrites the WHOLE ledger and re-chains it so the internal verify PASSES,
# but the anchors (published earlier) catch the divergence. Isolated pins.
set -u
OKNEKD=/tmp/oknekd-anc; OKNEK=/tmp/oknek-anc; WORK=/tmp/oknek-anc-e2e
PINDIR=/sys/fs/bpf/oknek-anc; CC=$(command -v cc||command -v gcc)
pass=0; fail=0
chk(){ if echo "$3"|grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $(echo "$3"|tr '\n' '~'|sed 's/~/ | /g')"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2]"; echo "$3"|sed 's/^/      /'; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ]&&kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/conn.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){ struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(atoi(v[2])); inet_pton(AF_INET,v[1],&a.sin_addr);
  int s=socket(AF_INET,SOCK_STREAM,0); fcntl(s,F_SETFL,O_NONBLOCK); connect(s,(struct sockaddr*)&a,sizeof a); return 0; }
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
for ip in 185.10.20.30 185.10.20.31 185.10.20.32; do OKNEK_AGENT=demo "$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" $ip 443 >/dev/null 2>&1; done
sleep 0.5
chk "seal anchor now" "sealed anchor #1 at head seq 3" "$("$OKNEK" --config "$WORK/oknek.yaml" okular anchor 2>&1)"
chk "anchors verify clean" "agrees with every published checkpoint" "$("$OKNEK" --config "$WORK/oknek.yaml" okular anchors 2>&1)"

# ATTACK: rewrite the whole ledger + re-chain it so the INTERNAL verify still passes
python3 - "$WORK/okular.db" <<'PY'
import sqlite3,hashlib,sys
def he(prev,ts,a,r,v,p): return hashlib.sha256(("%s\x1f%d\x1f%s\x1f%s\x1f%s\x1f%s"%(prev,ts,a,r,v,p)).encode()).hexdigest()
db=sqlite3.connect(sys.argv[1]); rows=list(db.execute("SELECT seq,ts,agent,rule,verdict,payload FROM okular_ledger ORDER BY seq"))
prev="okular-genesis-v1"
for seq,ts,a,r,v,p in rows:
    if seq==2: p='{"dest":"scrubbed"}'
    h=he(prev,ts,a,r,v,p); db.execute("UPDATE okular_ledger SET payload=?,prev_hash=?,hash=? WHERE seq=?",(p,prev,h,seq)); prev=h
db.commit(); print("re-chained whole ledger (internally consistent)")
PY

chk "regular verify is FOOLED (chain internally consistent)" "chain intact" "$("$OKNEK" --config "$WORK/oknek.yaml" okular 2>&1)"
chk "ANCHORS CATCH the rewrite  «divergence from a published checkpoint»" "REWRITTEN|✗" "$("$OKNEK" --config "$WORK/oknek.yaml" okular anchors 2>&1)"
echo "   anchors verdict:"; "$OKNEK" --config "$WORK/oknek.yaml" okular anchors 2>&1 | sed 's/^/      /'

echo "===== Okular anchoring: $pass passed, $fail failed ====="
exit "$fail"
