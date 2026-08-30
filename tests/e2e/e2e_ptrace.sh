#!/usr/bin/env bash
# R13 proof: a watched agent cannot read ANOTHER process's memory — the credential
# "memory lane" (process_vm_readv, /proc/<pid>/environ) is shut at lsm/ptrace_access_check.
# Self-reads (/proc/self/environ) still work (kernel short-circuits before the hook);
# unwatched reads still work (scoping); normal file reads unaffected. Isolated; prod
# untouched; cleaned up.
set -u
OKNEKD=/tmp/oknekd-r13; OKNEK=/tmp/oknek-r13; WORK=/tmp/oknek-r13-e2e
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
# isolated pin dir so this test NEVER clobbers the prod daemon's /sys/fs/bpf/oknek pins.
PINDIR=/sys/fs/bpf/oknek-r13test
DP=""; TP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; [ -n "$TP" ] && kill $TP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
echo "ALLOWED-CONTENT" > "$WORK/normal.txt"

# target: a victim process that exposes a secret's address, then sleeps forever.
cat > "$WORK/target.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
static char secret[64] = "TOPSECRETMEMORYVALUE";
int main(void){ printf("%d %p\n", getpid(), (void*)secret); fflush(stdout); pause(); return 0; }
EOF
# reader: process_vm_readv another process's memory.
cat > "$WORK/pvr.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
int main(int c,char**v){
  int target=atoi(v[1]); unsigned long addr=strtoul(v[2],0,0);
  char buf[64]; struct iovec loc={buf,sizeof buf}, rem={(void*)addr,sizeof buf};
  ssize_t n=process_vm_readv(target,&loc,1,&rem,1,0);
  if(n>=0){printf("READ_OK n=%zd\n",n);return 0;}
  printf("READ_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/target" "$WORK/target.c" || { echo "compile target failed"; exit 2; }
"$CC" -O2 -o "$WORK/pvr"    "$WORK/pvr.c"    || { echo "compile pvr failed"; exit 2; }

cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
EOF

# start the victim, grab its pid + secret address
"$WORK/target" > "$WORK/tinfo" & TP=$!
sleep 0.4
read TPID TADDR < "$WORK/tinfo"
echo "victim pid=$TPID secret@=$TADDR"

OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up, R3 enforcement live" "R3 enforcement live" "$(cat "$WORK/out")"

# 1. KEY — watched agent process_vm_readv of the victim is BLOCKED
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/pvr" "$TPID" "$TADDR" 2>&1)
chk "watched process_vm_readv of another proc BLOCKED  «memory lane shut»" "errno=1\(" "$A"

# 2. watched agent reading the victim's /proc/<pid>/environ is BLOCKED
B=$("$OKNEK" --config "$WORK/oknek.yaml" run cat "/proc/$TPID/environ" 2>&1)
chk "watched read of /proc/<victim>/environ BLOCKED" "not permitted|permission denied" "$B"

# 3. watched agent reading its OWN /proc/self/environ is ALLOWED (kernel self short-circuit)
C=$("$OKNEK" --config "$WORK/oknek.yaml" run cat /proc/self/environ 2>&1 | tr '\0' '\n')
chk "watched read of /proc/self/environ ALLOWED (self)" "PATH=" "$C"

# 4. UNWATCHED process_vm_readv of the victim is ALLOWED (scoping)
D=$("$WORK/pvr" "$TPID" "$TADDR" 2>&1)
chk "UNWATCHED process_vm_readv ALLOWED (scoping)" "READ_OK" "$D"

# 5. no over-block — watched agent reading a normal file is ALLOWED
E=$("$OKNEK" --config "$WORK/oknek.yaml" run cat "$WORK/normal.txt" 2>&1)
chk "watched read of a normal file ALLOWED" "ALLOWED-CONTENT" "$E"

echo "===== ptrace_access_check (R13 memory lane): $pass passed, $fail failed ====="
exit "$fail"
