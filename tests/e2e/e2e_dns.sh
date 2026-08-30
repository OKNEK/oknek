#!/usr/bin/env bash
# Class 5 (DNS) proof: with resolvers read from /etc/resolv.conf, :53 to a
# NON-resolver is blocked (DNS-tunnel exfil shut), :53 to the real resolver is
# allowed (DNS not broken). Isolated test daemon; prod untouched; cleaned up.
set -u
OKNEKD=/tmp/oknekd-dns; OKNEK=/tmp/oknek-dns; WORK=/tmp/oknek-dns-e2e
RES=$(grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
NONRES=185.10.20.30
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf /sys/fs/bpf/oknek 2>/dev/null' EXIT
rm -rf /sys/fs/bpf/oknek 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/conn.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){alarm(4);int p=atoi(v[2]);struct sockaddr_in a;memset(&a,0,sizeof a);
a.sin_family=AF_INET;a.sin_port=htons(p);inet_pton(AF_INET,v[1],&a.sin_addr);
int s=socket(AF_INET,SOCK_STREAM,0);
if(connect(s,(struct sockaddr*)&a,sizeof a)==0){printf("CONNECT_OK\n");return 0;}
printf("CONNECT_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/conn" "$WORK/conn.c" || { echo "cc failed"; exit 2; }
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/s.sock
db_path: $WORK/db
log_path: $WORK/log
rules_dir: $WORK/rules/active
egress_jail:
  enabled: true
  gateway: { host: "127.0.0.1", port: 4000 }
  enforce: true
EOF
"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
grep -E "R11 active" "$WORK/out" | sed 's/^/   /'
chk "R11 active + resolvers read (>=1, restrict ACTIVE)" "resolvers=[1-9]" "$(cat "$WORK/out")"
echo "   resolver=$RES   non-resolver=$NONRES"

# 1. KEY — :53 to a NON-resolver is BLOCKED (DNS-tunnel exfil shut)
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" "$NONRES" 53 2>&1)
chk ":53 to NON-resolver BLOCKED  «DNS-exfil shut»" "errno=1\(" "$A"

# 2. :53 to the configured resolver is ALLOWED (DNS not broken)
if [ -n "$RES" ]; then
  B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" "$RES" 53 2>&1)
  chk ":53 to configured resolver ALLOWED (DNS works)" "OK" "$(echo "$B" | grep -q 'errno=1(' && echo EPERM-BLOCKED || echo OK) :: $B"
else
  echo "SKIP: no nameserver in /etc/resolv.conf"
fi

# 3. control — non-:53 off-gateway still BLOCKED
C=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" "$NONRES" 443 2>&1)
chk "control: non-DNS off-gateway BLOCKED" "errno=1\(" "$C"

echo "===== resolver :53 (Class 5): $pass passed, $fail failed ====="
exit "$fail"
