#!/usr/bin/env bash
# Okredo v3: the per-agent allowlist now also covers connectionless UDP/QUIC
# (socket_sendmsg). Same identity-scoped CIDR grant -> UDP sendto allowed in range,
# blocked out of range / no profile. TCP regression intact. Isolated pins.
set -u
OKNEKD=/tmp/oknekd-okv3; OKNEK=/tmp/oknek-okv3; WORK=/tmp/oknek-okv3-e2e
PINDIR=/sys/fs/bpf/oknek-okv3; CC=$(command -v cc||command -v gcc)
pass=0; fail=0
chk(){ if echo "$3"|grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ]&&kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/udp.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){ struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(atoi(v[2])); inet_pton(AF_INET,v[1],&a.sin_addr);
  int s=socket(AF_INET,SOCK_DGRAM,0);
  ssize_t r=sendto(s,"x",1,0,(struct sockaddr*)&a,sizeof a);
  if(r>=0){printf("SENT\n");return 0;}
  printf("BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
cat > "$WORK/tcp.c" <<'EOF'
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
  int r=connect(s,(struct sockaddr*)&a,sizeof a);
  if(r==0||errno==EINPROGRESS){printf("ALLOWED\n");return 0;}
  printf("BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/udp" "$WORK/udp.c" && "$CC" -O2 -o "$WORK/tcp" "$WORK/tcp.c" || { echo compile-fail; exit 2; }
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
egress_jail: { enabled: true, gateway: { host: "127.0.0.1", port: 4000 }, enforce: true }
okredo: { enabled: true, profiles: { gh: { allow_egress: ["140.82.0.0/16:443"] } } }
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "okredo active" "okredo: 1 profile" "$(cat "$WORK/out")"
chk "UDP  gh -> 140.82.50.1:443 ALLOWED (sendmsg allowlist)" "SENT" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh "$WORK/udp" 140.82.50.1 443 2>&1)"
chk "UDP  gh -> 8.8.8.8:443 BLOCKED (out of range)" "errno=1\(" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh "$WORK/udp" 8.8.8.8 443 2>&1)"
chk "UDP  no-profile -> 140.82.50.1:443 BLOCKED (base jail)" "errno=1\(" "$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/udp" 140.82.50.1 443 2>&1)"
chk "TCP  gh -> 140.82.50.1:443 ALLOWED (connect regression)" "ALLOWED" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh "$WORK/tcp" 140.82.50.1 443 2>&1)"
echo "===== Okredo v3 (UDP allowlist): $pass passed, $fail failed ====="
exit "$fail"
