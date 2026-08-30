#!/usr/bin/env bash
# R16 proof: a watched agent cannot bind an externally-reachable listener (0.0.0.0
# / interface IP) — blocked at lsm/socket_bind. Loopback binds allowed; unwatched
# binds allowed (scoping). Isolated pins; prod untouched.
set -u
OKNEKD=/tmp/oknekd-r16; OKNEK=/tmp/oknek-r16; WORK=/tmp/oknek-r16-e2e
PINDIR=/sys/fs/bpf/oknek-r16test
CC=$(command -v cc || command -v gcc)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/bind.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){ int port=atoi(v[2]);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,v[1],&a.sin_addr);
  int s=socket(AF_INET,SOCK_STREAM,0); int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
  if(bind(s,(struct sockaddr*)&a,sizeof a)==0){printf("BIND_OK\n");return 0;}
  printf("BIND_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/bind" "$WORK/bind.c" || { echo compile-fail; exit 2; }
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up" "R3 enforcement live" "$(cat "$WORK/out")"
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/bind" 0.0.0.0 39001 2>&1)
chk "watched bind 0.0.0.0 BLOCKED  «backdoor listen shut»" "errno=1\(" "$A"
B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/bind" 127.0.0.1 39002 2>&1)
chk "watched bind 127.0.0.1 ALLOWED (loopback)" "BIND_OK" "$B"
C=$("$WORK/bind" 0.0.0.0 39003 2>&1)
chk "UNWATCHED bind 0.0.0.0 ALLOWED (scoping)" "BIND_OK" "$C"
echo "===== inbound-backdoor guard (R16): $pass passed, $fail failed ====="
exit "$fail"
