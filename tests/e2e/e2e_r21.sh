#!/usr/bin/env bash
# R21 proof: Meta's Agents Rule of Two, enforced by the kernel. A watched agent
# SESSION (identity, incl. every child it spawns) may hold at most two of
#   U untrusted input (read under an untrusted dir)   P private data (read a private file)
#   X external comms (identity-granted non-gateway connect)
# The syscall that would grant the THIRD returns -EPERM. observe mode logs the
# would-deny instead. `oknek taint clear` is the human checkpoint; a fresh
# `oknek run --agent` starts clean; unwatched processes are never touched.
set -u
OKNEKD=/tmp/oknekd-r21; OKNEK=/tmp/oknek-r21; WORK=/tmp/oknek-r21-e2e
CC=$(command -v cc || command -v gcc || command -v clang)
PINDIR=/sys/fs/bpf/oknek-r21test
DEST=185.10.20.30
pass=0; fail=0
chk(){ if echo "$3" | tr '\n' ' ' | grep -qE "$2"; then echo "PASS: $1"; echo "   |- $(echo "$3" | tr '\n' ' ' | head -c 170)"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$(echo "$3" | tr '\n' ' ' | head -c 200)]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active" "$WORK/bin" "$WORK/repo" "$WORK/private"

cat > "$WORK/bin/rd.c" <<'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
int main(int c,char**v){ int fd=open(v[1], O_RDONLY);
  if(fd>=0){printf("OPEN_OK %s\n", v[1]);close(fd);return 0;}
  printf("OPEN_BLOCKED errno=%d(%s) %s\n",errno,strerror(errno),v[1]);return 1;}
EOF
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
  if(r==0||errno==EINPROGRESS){printf("CONNECT_ALLOWED %s:%s\n",v[1],v[2]);return 0;}
  printf("CONNECT_BLOCKED errno=%d(%s) %s:%s\n",errno,strerror(errno),v[1],v[2]);return 1;}
EOF
"$CC" -O2 -o "$WORK/bin/rd" "$WORK/bin/rd.c" && "$CC" -O2 -o "$WORK/bin/conn" "$WORK/bin/conn.c" || { echo "compile failed"; exit 2; }
RD="$WORK/bin/rd"; CONN="$WORK/bin/conn"
echo "# untrusted repo" > "$WORK/repo/README.md"; echo "more" > "$WORK/repo/other.md"
echo "customer rows" > "$WORK/private/customer.db"
U="$WORK/repo/README.md"; U2="$WORK/repo/other.md"; P="$WORK/private/customer.db"

cat > "$WORK/oknek.yaml" <<EOF
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
    r2e:
      allow_egress: ["$DEST:443"]
      rule_of_two: enforce
    r2o:
      allow_egress: ["$DEST:443"]
      rule_of_two: observe
    plain:
      allow_egress: ["$DEST:443"]
rule_of_two:
  untrusted_dirs: ["$WORK/repo"]
  private_files: ["$P"]
EOF

OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 2
chk "daemon up, R21 armed" "rule_of_two: R21 armed .*1 dir.*1 enforce, 1 observe" "$(cat "$WORK/out")"
run(){ "$OKNEK" --config "$WORK/oknek.yaml" run --agent "$1" --profile "$2" -- /bin/bash -c "$3" 2>&1; }

# 1. (U,P) -> X DENIED
A=$(run s1 r2e "$RD $U; $RD $P; $CONN $DEST 443")
chk "(U,P) then connect -> X DENIED at the kernel" "OPEN_OK.*OPEN_OK.*CONNECT_BLOCKED errno=1\(" "$A"
# 2. (U,X) -> P DENIED
B=$(run s2 r2e "$RD $U; $CONN $DEST 443; $RD $P")
chk "(U,X) then private read -> P DENIED" "OPEN_OK.*CONNECT_ALLOWED.*OPEN_BLOCKED errno=1\(" "$B"
# 3. default network=untrusted: after private data, an external connect is U+X = third -> DENIED
C=$(run s3 r2e "$RD $P; $CONN $DEST 443")
chk "(P) then connect -> DENIED (default: network is untrusted, connect = U+X)" "OPEN_OK.*CONNECT_BLOCKED errno=1\(" "$C"
# 4. any two is fine; a second untrusted read adds nothing
D=$(run s4 r2e "$RD $U; $RD $P; $RD $U2")
chk "two properties only -> everything allowed" "OPEN_OK.*OPEN_OK.*OPEN_OK" "$D"
# 5. child processes taint the SESSION (cat is a child of bash)
E=$(run s5 r2e "cat $U >/dev/null; cat $P >/dev/null; $CONN $DEST 443")
chk "taint acquired by child cat's applies to the session -> connect DENIED" "CONNECT_BLOCKED errno=1\(" "$E"
# 6. observe profile: allowed, but would-deny recorded
F=$(run s6 r2o "$RD $U; $RD $P; $CONN $DEST 443")
chk "observe profile: third property ALLOWED" "CONNECT_ALLOWED" "$F"
# 7. plain profile (no rule_of_two): untouched
G=$(run s7 plain "$RD $U; $RD $P; $CONN $DEST 443")
chk "profile without rule_of_two: untouched" "OPEN_OK.*OPEN_OK.*CONNECT_ALLOWED" "$G"
# 8. taint readout
T=$("$OKNEK" --config "$WORK/oknek.yaml" taint 2>&1)
chk "oknek taint lists s1 with U+P (one more = DENIED)" "s1 .*\[U P ·\].*DENIED" "$T"
chk "oknek taint lists s2 with U+X" "s2 .*\[U · X\]" "$T"
chk "R21 events recorded" "R21 Rule of Two .* [1-9][0-9]* event" "$T"
# 9. human checkpoint inside a live session: clear then the third is allowed
H=$(run s8 r2e "$RD $U; $RD $P; $OKNEK --config $WORK/oknek.yaml taint clear s8 --note e2e-review >/dev/null; $CONN $DEST 443")
chk "taint clear mid-session -> connect ALLOWED" "OPEN_OK.*OPEN_OK.*CONNECT_ALLOWED" "$H"
# 10. a fresh `oknek run --agent s1` is a NEW session (clean)
I=$(run s1 r2e "$CONN $DEST 443")
chk "fresh session with an old name starts clean" "CONNECT_ALLOWED" "$I"
# 11. unwatched: never touched
J=$("$RD" "$U"; "$RD" "$P"; "$CONN" "$DEST" 443)
chk "unwatched process untouched" "OPEN_OK.*OPEN_OK.*CONNECT_ALLOWED" "$(echo "$J" | tr '\n' ' ')"
# 12. Okular sealed the checkpoint
K=$("$OKNEK" --config "$WORK/oknek.yaml" replay oknekd 2>&1)
chk "okular sealed taint_clear" "taint_clear" "$K"
DOC=$("$OKNEK" --config "$WORK/oknek.yaml" doctor 2>&1)
chk "doctor shows rule of two" "rule of two" "$DOC"

# --- phase 2: network_trusted: true -> pure Meta semantics (connect = X only) ---
kill $DP; wait $DP 2>/dev/null; DP=""
sed -i 's/^rule_of_two:$/rule_of_two:\n  network_trusted: true/' "$WORK/oknek.yaml"
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out2" 2>&1 & DP=$!
sleep 2
chk "phase 2: network=trusted armed" "network=trusted" "$(cat "$WORK/out2")"
L=$(run s9 r2e "$RD $P; $CONN $DEST 443; $RD $U")
chk "network_trusted: (P,X) then untrusted read -> U DENIED" "OPEN_OK.*CONNECT_ALLOWED.*OPEN_BLOCKED errno=1\(" "$L"
M=$(run s10 r2e "$RD $P; $CONN $DEST 443; $CONN $DEST 443")
chk "network_trusted: (P,X) more connects fine" "OPEN_OK.*CONNECT_ALLOWED.*CONNECT_ALLOWED" "$M"

echo; echo "R21 e2e: $pass pass, $fail fail"
kill $DP 2>/dev/null; DP=""
[ $fail -eq 0 ]
