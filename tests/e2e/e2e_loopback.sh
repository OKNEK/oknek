#!/usr/bin/env bash
# Class-5 residual proof: loopback is restricted to the gateway port + local DNS.
# A watched agent can reach 127.0.0.1:<gateway> and :53, but NOT an arbitrary
# loopback port — so it can't pivot out through an unwatched local forwarder.
# EPERM(errno 1)=LSM-blocked; ECONNREFUSED(errno 111)=LSM-allowed (nothing listening).
set -u
OKNEKD=/tmp/oknekd-lb; OKNEK=/tmp/oknek-lb; WORK=/tmp/oknek-lb-e2e
PINDIR=/sys/fs/bpf/oknek-lbtest; CC=$(command -v cc||command -v gcc)
pass=0; fail=0
chk(){ if echo "$3"|grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ]&&kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/conn.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){ int port=atoi(v[2]);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,v[1],&a.sin_addr);
  int s=socket(AF_INET,SOCK_STREAM,0);
  if(connect(s,(struct sockaddr*)&a,sizeof a)==0){printf("CONNECTED\n");return 0;}
  printf("CONN_ERR errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/conn" "$WORK/conn.c" || { echo compile-fail; exit 2; }
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
egress_jail:
  enabled: true
  gateway: { host: "127.0.0.1", port: 4000 }
  block_dns: false
  enforce: true
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up, R11 enforcing" "R11 active" "$(cat "$WORK/out")"
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" 127.0.0.1 4000 2>&1)
chk "watched loopback->GATEWAY port 4000 ALLOWED" "errno=111|CONNECTED" "$A"
B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" 127.0.0.1 9999 2>&1)
chk "watched loopback->OTHER port 9999 BLOCKED  «proxy-pivot shut»" "errno=1\(" "$B"
C=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" 127.0.0.53 53 2>&1)
chk "watched loopback->local DNS :53 ALLOWED" "errno=111|CONNECTED" "$C"
D=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" 1.2.3.4 443 2>&1)
chk "watched off-gateway external BLOCKED (R11 intact)" "errno=1\(" "$D"
E=$("$WORK/conn" 127.0.0.1 9999 2>&1)
chk "UNWATCHED loopback->9999 ALLOWED (scoping)" "errno=111|CONNECTED" "$E"
echo "===== loopback-pivot residual (Class 5): $pass passed, $fail failed ====="
exit "$fail"
