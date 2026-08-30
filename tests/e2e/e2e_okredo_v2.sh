#!/usr/bin/env bash
# Okredo v2: CIDR range grants + policy fork-propagation. A profile can authorize a
# whole /16; a watched agent's CHILD processes inherit the identity's grants.
# EPERM(errno1)=blocked; EINPROGRESS=allowed(SYN in flight). Isolated pins.
set -u
OKNEKD=/tmp/oknekd-okv2; OKNEK=/tmp/oknek-okv2; WORK=/tmp/oknek-okv2-e2e
PINDIR=/sys/fs/bpf/oknek-okv2; CC=$(command -v cc||command -v gcc)
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
int main(int c,char**v){ struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(atoi(v[2])); inet_pton(AF_INET,v[1],&a.sin_addr);
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
egress_jail: { enabled: true, gateway: { host: "127.0.0.1", port: 4000 }, enforce: true }
okredo:
  enabled: true
  profiles:
    gh: { allow_egress: ["140.82.0.0/16:443"] }
    exact: { allow_egress: ["1.2.3.4:443"] }
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "okredo loaded (2 profiles, grants)" "okredo: 2 profile.s., 2 egress grant" "$(cat "$WORK/out")"

# CIDR range: two different IPs in 140.82.0.0/16 both authorized
chk "CIDR  gh -> 140.82.50.1:443 ALLOWED" "ALLOWED"  "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh "$WORK/conn" 140.82.50.1 443 2>&1)"
chk "CIDR  gh -> 140.82.211.9:443 ALLOWED (whole /16)" "ALLOWED" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh "$WORK/conn" 140.82.211.9 443 2>&1)"
chk "CIDR  gh -> 8.8.8.8:443 BLOCKED (out of range)" "errno=1\(" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh "$WORK/conn" 8.8.8.8 443 2>&1)"
chk "CIDR  gh -> 140.82.50.1:80 BLOCKED (port-scoped)" "errno=1\(" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh "$WORK/conn" 140.82.50.1 80 2>&1)"
# exact-IP regression
chk "exact exact -> 1.2.3.4:443 ALLOWED (v1 regression)" "ALLOWED" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile exact "$WORK/conn" 1.2.3.4 443 2>&1)"
# fork-propagation: a CHILD of the profiled agent inherits the grant
chk "fork  gh's child -> 140.82.50.1:443 ALLOWED (policy inherited)" "ALLOWED" "$("$OKNEK" --config "$WORK/oknek.yaml" run --profile gh sh -c "$WORK/conn 140.82.50.1 443" 2>&1)"
# control: no-profile child -> base jail
chk "fork  no-profile child -> 140.82.50.1:443 BLOCKED (base jail)" "errno=1\(" "$("$OKNEK" --config "$WORK/oknek.yaml" run sh -c "$WORK/conn 140.82.50.1 443" 2>&1)"

echo "===== Okredo v2 (CIDR + fork-prop): $pass passed, $fail failed ====="
exit "$fail"
