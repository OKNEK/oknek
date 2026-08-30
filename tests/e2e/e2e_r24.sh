#!/usr/bin/env bash
# R24 proof: MCP server jail. An agent's .mcp.json declares stdio servers alpha
# (no grants) and beta (granted DEST:443) plus a remote http server. In ENFORCE
# mode each spawned stdio server is bound to its own kernel identity: alpha's
# connect is BLOCKED and reported as R24 with the server name; beta's is allowed;
# the agent's own child keeps the agent's grants. In OBSERVE mode nothing is bound
# and `oknek mcp` shows what alpha actually reached. Isolated pins; prod untouched.
set -u
OKNEKD=/tmp/oknekd-r24; OKNEK=/tmp/oknek-r24; WORK=/tmp/oknek-r24-e2e
CC=$(command -v cc || command -v gcc || command -v clang)
PINDIR=/sys/fs/bpf/oknek-r24test
DEST=185.10.20.30
pass=0; fail=0
chk(){ if echo "$3" | tr '\n' ' ' | grep -qE "$2"; then echo "PASS: $1"; echo "   |- $(echo "$3" | tr '\n' ' ' | head -c 170)"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$(echo "$3" | tr '\n' ' ' | head -c 220)]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active" "$WORK/bin"

cat > "$WORK/bin/conn.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int c,char**v){ int s=socket(AF_INET,SOCK_STREAM,0); fcntl(s,F_SETFL,O_NONBLOCK);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(atoi(v[2])); inet_pton(AF_INET,v[1],&a.sin_addr);
  int r=connect(s,(struct sockaddr*)&a,sizeof a);
  if(r==0||errno==EINPROGRESS){printf("%s:CONNECT_ALLOWED\n",v[3]);return 0;}
  printf("%s:CONNECT_BLOCKED errno=%d\n",v[3],errno);return 1;}
EOF
"$CC" -O2 -o "$WORK/bin/conn" "$WORK/bin/conn.c" || { echo "compile failed"; exit 2; }
CONN="$WORK/bin/conn"
# stdio "servers": scripts that connect out after a short settle (bind lands within ms of exec)
printf '#!/bin/bash\nsleep 0.3\n%s %s 443 alpha\n' "$CONN" "$DEST" > "$WORK/srvA"; chmod +x "$WORK/srvA"
printf '#!/bin/bash\nsleep 0.3\n%s %s 443 beta\n'  "$CONN" "$DEST" > "$WORK/srvB"; chmod +x "$WORK/srvB"
cat > "$WORK/.mcp.json" <<EOF
{"mcpServers":{
  "alpha": {"command": "$WORK/srvA", "args": ["--name", "alpha"]},
  "beta":  {"command": "$WORK/srvB", "args": ["--name", "beta"]},
  "docs":  {"type": "http", "url": "http://$DEST:443/mcp"}
}}
EOF

mkcfg(){ cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
okular:
  enabled: true
egress_jail:
  enabled: true
  gateway: { host: "127.0.0.1", port: 4000 }
  enforce: true
okredo:
  enabled: true
  profiles:
    agent:
      allow_egress: ["$DEST:443"]
mcp:
  enabled: true
  enforce: $1
  grants:
    beta: ["$DEST:443"]
EOF
}
mkcfg true
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 2
chk "daemon up, R24 ENFORCE" "mcp: R24 MCP server jail ENABLED .*ENFORCE" "$(cat "$WORK/out")"

cd "$WORK"
A=$("$OKNEK" --config "$WORK/oknek.yaml" run --agent m1 --profile agent -- /bin/bash -c "$WORK/srvA --name alpha; $WORK/srvB --name beta; $CONN $DEST 443 self" 2>&1)
chk "manifest read at session start: 3 servers, 2 stdio jailed, 1 remote" "declares 3 MCP server.s. — 2 stdio jailed, 1 remote" "$(cat "$WORK/out")"
chk "alpha (no grants) connect BLOCKED at the kernel" "alpha:CONNECT_BLOCKED errno=1" "$A"
chk "beta (granted) connect ALLOWED" "beta:CONNECT_ALLOWED" "$A"
chk "agent's own child keeps the agent's grants" "self:CONNECT_ALLOWED" "$A"
chk "alpha/beta bound to their own policies" "m1/alpha exec'd .*bound to policy [0-9]+.*m1/beta exec'd .*bound to policy [0-9]+" "$(cat "$WORK/out")"
sleep 0.5
M=$("$OKNEK" --config "$WORK/oknek.yaml" mcp 2>&1)
chk "oknek mcp: alpha jailed with 1 block" "m1/alpha .*stdio .*jailed · policy [0-9]+.*blocks: 1" "$M"
chk "oknek mcp: beta jailed, 0 blocks, grant listed" "m1/beta .*jailed · policy [0-9]+.*grants: +$DEST:443.*blocks: 0" "$M"
chk "oknek mcp: docs reported as remote" "m1/docs .*http .*remote" "$M"
EG=$("$OKNEK" --config "$WORK/oknek.yaml" egress 2>&1)
R=$("$OKNEK" --config "$WORK/oknek.yaml" replay m1 2>&1)
chk "block sealed in Okular as R24 (server named)" "R24" "$R"

# unwatched: the same script is untouched
U=$("$WORK/srvA" --name alpha 2>&1)
chk "unwatched srvA untouched" "alpha:CONNECT_ALLOWED" "$U"

# --- observe mode ---
kill $DP; wait $DP 2>/dev/null; DP=""
mkcfg false
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out2" 2>&1 & DP=$!
sleep 2
chk "observe mode armed" "mcp: R24 MCP server jail ENABLED .*OBSERVE" "$(cat "$WORK/out2")"
B=$("$OKNEK" --config "$WORK/oknek.yaml" run --agent m2 --profile agent -- /bin/bash -c "$WORK/srvA --name alpha" 2>&1)
chk "observe: alpha judged by the agent's policy -> ALLOWED" "alpha:CONNECT_ALLOWED" "$B"
sleep 0.5
M2=$("$OKNEK" --config "$WORK/oknek.yaml" mcp 2>&1)
chk "observe: oknek mcp shows what alpha reached" "m2/alpha .*observing.*reached: +$DEST:443" "$M2"

echo; echo "R24 e2e: $pass pass, $fail fail"
kill $DP 2>/dev/null; DP=""
[ $fail -eq 0 ]
