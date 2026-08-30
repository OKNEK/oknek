#!/usr/bin/env bash
# Class 1 proof: UDP sendto (connectionless, never calls connect) to an off-gateway
# dest is now BLOCKED by the socket_sendmsg hook; loopback allowed; TCP still gated
# (regression); unwatched allowed (scoping). Isolated; prod untouched; cleaned up.
set -u
OKNEKD=/tmp/oknekd-sm; OKNEK=/tmp/oknek-sm; WORK=/tmp/oknek-sm-e2e
NONRES=185.10.20.30
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf /sys/fs/bpf/oknek 2>/dev/null' EXIT
rm -rf /sys/fs/bpf/oknek 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/udp.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){int p=atoi(v[2]);struct sockaddr_in a;memset(&a,0,sizeof a);
a.sin_family=AF_INET;a.sin_port=htons(p);inet_pton(AF_INET,v[1],&a.sin_addr);
int s=socket(AF_INET,SOCK_DGRAM,0);
ssize_t r=sendto(s,"x",1,0,(struct sockaddr*)&a,sizeof a);
if(r>=0){printf("SENT_OK\n");return 0;}
printf("SENT_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
cat > "$WORK/tcp.c" <<'EOF'
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
"$CC" -O2 -o "$WORK/udp" "$WORK/udp.c" && "$CC" -O2 -o "$WORK/tcp" "$WORK/tcp.c" || { echo cc failed; exit 2; }
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
chk "R11 active (enforce)" "R11 active" "$(cat "$WORK/out")"

# 1. KEY — watched UDP sendto to off-gateway BLOCKED (the connectionless hole)
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/udp" "$NONRES" 5000 2>&1)
chk "watched UDP sendto off-gateway BLOCKED  «route-around hole shut»" "errno=1\(" "$A"

# 2. watched UDP sendto to loopback ALLOWED
B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/udp" 127.0.0.1 5000 2>&1)
chk "watched UDP sendto loopback ALLOWED" "SENT_OK" "$B"

# 3. regression — watched TCP connect off-gateway still BLOCKED
C=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/tcp" "$NONRES" 5000 2>&1)
chk "regression: watched TCP connect off-gateway BLOCKED" "errno=1\(" "$C"

# 4. scoping — UNWATCHED UDP sendto off-gateway ALLOWED
D=$("$WORK/udp" "$NONRES" 5000 2>&1)
chk "UNWATCHED UDP sendto ALLOWED (scoping)" "SENT_OK" "$D"

echo "===== socket_sendmsg (Class 1): $pass passed, $fail failed ====="
exit "$fail"
