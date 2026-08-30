#!/usr/bin/env bash
# Okredo (IAM) proof: per-agent identity -> authorization. With the base egress jail
# enforcing, a watched agent's *profile* decides which destinations it may reach.
# Headline: the SAME destination is ALLOWED for one identity and BLOCKED for another.
# EPERM(errno 1)=LSM-blocked; EINPROGRESS=LSM-allowed (SYN in flight). Isolated pins.
set -u
OKNEKD=/tmp/oknekd-ok; OKNEK=/tmp/oknek-ok; WORK=/tmp/oknek-ok-e2e
PINDIR=/sys/fs/bpf/oknek-oktest; CC=$(command -v cc||command -v gcc)
DEST=185.10.20.30; OTHER=185.10.20.40
pass=0; fail=0
chk(){ if echo "$3"|grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
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
int main(int c,char**v){ int port=atoi(v[2]);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,v[1],&a.sin_addr);
  int s=socket(AF_INET,SOCK_STREAM,0); fcntl(s,F_SETFL,O_NONBLOCK);
  int r=connect(s,(struct sockaddr*)&a,sizeof a);
  if(r==0||errno==EINPROGRESS){printf("ALLOWED\n");return 0;}
  printf("BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
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
  enforce: true
okredo:
  enabled: true
  profiles:
    github:
      allow_egress: ["$DEST:443"]
    locked:
      allow_egress: []
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up, okredo active" "okredo: 2 profile.s., 1 egress grant" "$(cat "$WORK/out")"

# 1+2 HEADLINE — SAME dest, different identity, different verdict
A=$("$OKNEK" --config "$WORK/oknek.yaml" run --profile github "$WORK/conn" $DEST 443 2>&1)
chk "identity 'github'  -> $DEST:443 ALLOWED  «authorized»" "ALLOWED" "$A"
B=$("$OKNEK" --config "$WORK/oknek.yaml" run --profile locked "$WORK/conn" $DEST 443 2>&1)
chk "identity 'locked'  -> $DEST:443 BLOCKED  «same dest, not authorized»" "errno=1\(" "$B"

# 3. github authorized for DEST only, not OTHER
C=$("$OKNEK" --config "$WORK/oknek.yaml" run --profile github "$WORK/conn" $OTHER 443 2>&1)
chk "identity 'github'  -> $OTHER:443 BLOCKED (grant is dest-scoped)" "errno=1\(" "$C"

# 4. no profile -> base jail (off-gateway blocked)
D=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/conn" $DEST 443 2>&1)
chk "no identity        -> $DEST:443 BLOCKED (base jail)" "errno=1\(" "$D"

# 5. github can still reach the gateway (base jail intact)
E=$("$OKNEK" --config "$WORK/oknek.yaml" run --profile github "$WORK/conn" 127.0.0.1 4000 2>&1)
chk "identity 'github'  -> gateway 127.0.0.1:4000 ALLOWED (base intact)" "ALLOWED" "$E"

echo "===== Okredo per-agent authorization: $pass passed, $fail failed ====="
exit "$fail"
