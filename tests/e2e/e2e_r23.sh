#!/usr/bin/env bash
# R23 proof: canary credentials. `oknek canary plant` drops decoys only where no real
# file exists. In alert mode a watched agent's open SUCCEEDS but fires a critical R23
# event (the alarm is the point — works even before you flip enforcement). In block
# mode the open is denied at file_open. Unwatched opens never fire. Removal never
# deletes a decoy whose bytes changed. Isolated pins; prod untouched.
set -u
OKNEKD=/tmp/oknekd-r23; OKNEK=/tmp/oknek-r23; WORK=/tmp/oknek-r23-e2e
CC=$(command -v cc || command -v gcc || command -v clang)
PINDIR=/sys/fs/bpf/oknek-r23test
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $(echo "$3" | head -c 160)"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active" "$WORK/home"

cat > "$WORK/rw.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
int main(int c,char**v){ int fd=open(v[1], O_RDONLY);
  if(fd>=0){printf("OPEN_OK\n");close(fd);return 0;}
  printf("OPEN_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/rw" "$WORK/rw.c" || { echo "compile failed"; exit 2; }

REAL="$WORK/home/secrets.json"; DECOY="$WORK/home/.aws/credentials"
echo '{"real":true}' > "$REAL"

mkcfg(){ cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
okular:
  enabled: true
canary:
  enabled: true
  mode: $1
  plant: ["$DECOY", "$REAL"]
EOF
}
mkcfg alert
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 2
chk "daemon up (kernel enforcement)" "R3 enforcement live" "$(cat "$WORK/out")"

P=$("$OKNEK" --config "$WORK/oknek.yaml" canary plant 2>&1)
chk "plant: 1 planted, real file skipped" "1 decoy\(s\) planted" "$P"
chk "  …real secrets.json NOT touched" "secrets.json.*NOT touched" "$P"
chk "  …real file bytes intact" '"real":true' "$(cat "$REAL")"
chk "decoy looks like AWS creds" "aws_access_key_id = AKIA" "$(cat "$DECOY")"

# 1. alert mode: watched open SUCCEEDS but fires R23
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$DECOY" 2>&1)
chk "alert mode: watched open allowed" "OPEN_OK" "$A"
sleep 0.5
S=$("$OKNEK" --config "$WORK/oknek.yaml" canary status 2>&1)
chk "…but R23 canary hit recorded" "hits 1" "$S"
# 2. unwatched open: no hit
"$WORK/rw" "$DECOY" >/dev/null 2>&1
sleep 0.5
S2=$("$OKNEK" --config "$WORK/oknek.yaml" canary status 2>&1)
chk "unwatched open does NOT fire (scoped)" "hits 1" "$S2"
# 3. reported as R23 (canary), not R3 (real cred) — the decoy sits at ~/.aws/credentials
EV=$("$OKNEK" --config "$WORK/oknek.yaml" status 2>&1)
chk "status reachable" "oknek" "$EV"

# 4. block mode: restart daemon, canaries re-armed from the store with block=1
kill $DP; wait $DP 2>/dev/null; DP=""
mkcfg block
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out2" 2>&1 & DP=$!
sleep 2
chk "restart re-armed 1 canary" "1 canaries \(mode block\)" "$(cat "$WORK/out2")"
B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$DECOY" 2>&1)
chk "block mode: watched open BLOCKED (shim EACCES or kernel EPERM)" "errno=(1|13)\(" "$B"
sleep 0.5
S3=$("$OKNEK" --config "$WORK/oknek.yaml" canary status 2>&1)
chk "block mode: hit still recorded" "hits 2" "$S3"
C=$("$WORK/rw" "$DECOY" 2>&1)
chk "block mode: unwatched open allowed" "OPEN_OK" "$C"

# 5. remove: decoy gone, real file untouched
R=$("$OKNEK" --config "$WORK/oknek.yaml" canary remove 2>&1)
chk "canary remove" "1 decoy\(s\) removed" "$R"
[ -f "$DECOY" ] && chk "decoy removed" "x" "still-there" || chk "decoy removed" "gone" "gone"
chk "real file still intact" '"real":true' "$(cat "$REAL")"

# 6. okular sealed plant + remove
T=$("$OKNEK" --config "$WORK/oknek.yaml" replay oknekd 2>&1)
chk "okular sealed canary_plant" "canary_plant" "$T"
chk "okular sealed canary_remove" "canary_remove" "$T"

echo; echo "R23 e2e: $pass pass, $fail fail"
kill $DP 2>/dev/null; DP=""
[ $fail -eq 0 ]
