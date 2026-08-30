#!/usr/bin/env bash
# Okular signed export: `oknek okular export` emits an ed25519-signed bundle of an
# agent's sealed timeline; `oknek okular verify-export` checks it OFFLINE. Tamper
# the bundle file -> verify FAILS (signature + chain both break). Isolated pins.
set -u
OKNEKD=/tmp/oknekd-oke; OKNEK=/tmp/oknek-oke; WORK=/tmp/oknek-oke-e2e
PINDIR=/sys/fs/bpf/oknek-oke; CC=$(command -v cc||command -v gcc)
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
for ip in 185.10.20.30 185.10.20.31 185.10.20.32; do OKNEK_AGENT=demo-agent "$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" $ip 443 >/dev/null 2>&1; done
sleep 0.6

"$OKNEK" --config "$WORK/oknek.yaml" okular export demo-agent > "$WORK/bundle.json" 2>/dev/null
echo "--- bundle head ---"; head -c 240 "$WORK/bundle.json"; echo "..."
chk "export produced a signed bundle" "okular-export-v1.*signature|signature" "$(cat "$WORK/bundle.json")"

V=$("$OKNEK" --config "$WORK/oknek.yaml" okular verify-export "$WORK/bundle.json" 2>&1)
chk "verify-export: SEALED & VERIFIED" "SEALED & VERIFIED" "$V"

# tamper: rewrite a recorded destination inside the sealed bundle
sed -i 's/185.10.20.31/9.9.9.9/' "$WORK/bundle.json"
W=$("$OKNEK" --config "$WORK/oknek.yaml" okular verify-export "$WORK/bundle.json" 2>&1)
chk "tampered bundle: signature INVALID + chain BROKEN -> FAILED" "FAILED" "$W"
echo "   tamper verify detail:"; echo "$W" | sed 's/^/      /'

echo "===== Okular signed export: $pass passed, $fail failed ====="
exit "$fail"
