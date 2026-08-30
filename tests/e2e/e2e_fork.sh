#!/usr/bin/env bash
# Proves fork-time watch propagation: a watched agent that double-forks and
# re-parents its grandchild to init (escaping the ancestry walk) is STILL blocked,
# because the child was marked watched at fork. Isolated test daemon; prod untouched.
set -u
OKNEKD=/tmp/oknekd-fork; OKNEK=/tmp/oknek-fork; WORK=/tmp/oknek-fork-e2e
GW_IP=127.0.0.1; GW_PORT=4000
EXT_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
chk(){ if echo "$3" | grep -q "$2"; then echo "PASS: $1"; echo "      └ $3"; pass=$((pass+1)); else echo "FAIL: $1 — want [$2] got [$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null' EXIT
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"

cat > "$WORK/conn.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){int p=atoi(v[2]);struct sockaddr_in a;memset(&a,0,sizeof a);
a.sin_family=AF_INET;a.sin_port=htons(p);inet_pton(AF_INET,v[1],&a.sin_addr);
int s=socket(AF_INET,SOCK_STREAM,0);
if(connect(s,(struct sockaddr*)&a,sizeof a)==0){printf("CONNECT_OK\n");return 0;}
printf("CONNECT_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/conn" "$WORK/conn.c" || { echo "cc conn failed"; exit 2; }

# double-fork: W forks C, C forks G, C exits -> G reparents to init, waits, connects, writes result
cat > "$WORK/dfork.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc,char**argv){const char*ip=argv[1];int port=atoi(argv[2]);const char*rf=argv[3];
 pid_t c=fork(); if(c<0)return 1;
 if(c>0){waitpid(c,0,0);usleep(600000);return 0;}
 pid_t g=fork(); if(g>0)_exit(0);            /* C exits -> G reparents to init */
 usleep(300000);
 int s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a;memset(&a,0,sizeof a);
 a.sin_family=AF_INET;a.sin_port=htons(port);inet_pton(AF_INET,ip,&a.sin_addr);
 int r=connect(s,(struct sockaddr*)&a,sizeof a);
 FILE*f=fopen(rf,"w");
 if(r==0)fprintf(f,"CONNECT_OK\n");else fprintf(f,"CONNECT_BLOCKED errno=%d(%s)\n",errno,strerror(errno));
 fclose(f);_exit(0);}
EOF
"$CC" -O2 -o "$WORK/dfork" "$WORK/dfork.c" || { echo "cc dfork failed"; exit 2; }

cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
egress_jail:
  enabled: true
  gateway: { host: "$GW_IP", port: $GW_PORT }
  enforce: true
EOF

"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/d.out" 2>&1 & DP=$!
sleep 1.6
grep -E "egress_jail: R11 active" "$WORK/d.out" | sed 's/^/      /'
chk "R11 active (enforce)" "R11 active" "$(cat "$WORK/d.out")"

# 1. regression — direct watched child is still blocked
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" "$EXT_IP" 5000 2>&1)
chk "direct watched child off-gateway BLOCKED (regression)" "errno=1(" "$A"

# 2. THE KEYSTONE — double-forked, reparented-to-init grandchild is blocked
rm -f "$WORK/g.out"
"$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/dfork" "$EXT_IP" 5000 "$WORK/g.out" >/dev/null 2>&1
sleep 1.2
chk "DOUBLE-FORK reparented grandchild BLOCKED  «THE KEYSTONE»" "errno=1(" "$(cat "$WORK/g.out" 2>/dev/null)"

# 3. scoping — an UNWATCHED double-fork is allowed (no listener -> ECONNREFUSED errno=111, NOT EPERM)
rm -f "$WORK/u.out"
"$WORK/dfork" "$EXT_IP" 5000 "$WORK/u.out" >/dev/null 2>&1
sleep 1.2
U=$(cat "$WORK/u.out" 2>/dev/null)
chk "UNWATCHED double-fork ALLOWED (scoping: not errno=1)" "OK" "$(echo "$U" | grep -q 'errno=1(' && echo EPERM-BLOCKED || echo OK) · $U"

echo "================ fork-prop e2e: $pass passed, $fail failed ================"
exit "$fail"
