#!/usr/bin/env bash
# R17 proof: a watched agent cannot call bpf() — blocked at lsm/bpf (anti-rootkit /
# self-defense; can't load a BPF rootkit or detach oknek). Unwatched bpf() allowed
# (scoping). The daemon's OWN bpf() (RegisterPID) must still work — proven by the
# watched test running at all. Isolated pins; prod untouched.
set -u
OKNEKD=/tmp/oknekd-r17; OKNEK=/tmp/oknek-r17; WORK=/tmp/oknek-r17-e2e
PINDIR=/sys/fs/bpf/oknek-r17test
CC=$(command -v cc || command -v gcc)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/bpfcall.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(){ char attr[128]; memset(attr,0,sizeof attr);
  long r=syscall(SYS_bpf, 12 /*BPF_PROG_GET_NEXT_ID*/, attr, sizeof attr);
  if(r>=0){printf("BPF_OK\n");return 0;}
  printf("BPF_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/bpfcall" "$WORK/bpfcall.c" || { echo compile-fail; exit 2; }
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up (its own bpf() works)" "R3 enforcement live" "$(cat "$WORK/out")"
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/bpfcall" 2>&1)
chk "watched bpf() BLOCKED  «can't load rootkit / detach oknek»" "errno=1\(" "$A"
B=$("$WORK/bpfcall" 2>&1)
chk "UNWATCHED bpf() ALLOWED (scoping)" "BPF_OK" "$B"
echo "===== kernel-tamper guard (R17): $pass passed, $fail failed ====="
exit "$fail"
