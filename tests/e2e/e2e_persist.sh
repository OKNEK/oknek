#!/usr/bin/env bash
# R14 proof: a watched agent cannot WRITE to persistence/backdoor locations (cron,
# authorized_keys, ld.so.preload, sudoers, shell rc) — blocked at file_open when
# FMODE_WRITE is set. READING the same files is allowed (R14 guards writes only);
# normal writes allowed (no over-block); unwatched writes allowed (scoping). The
# match is on (parent-dir basename, filename), so a sandbox $WORK/etc/... exercises
# it without touching real system files. Isolated pins; prod untouched; cleaned up.
set -u
OKNEKD=/tmp/oknekd-r14; OKNEK=/tmp/oknek-r14; WORK=/tmp/oknek-r14-e2e
CC=$(command -v cc || command -v gcc || command -v clang)
PINDIR=/sys/fs/bpf/oknek-r14test
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active" "$WORK/etc" "$WORK/.ssh" "$WORK/home" "$WORK/x/cron.d"

# rw helper: open(path, write?O_WRONLY|O_CREAT|O_APPEND:O_RDONLY)
cat > "$WORK/rw.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
int main(int c,char**v){ int wr=atoi(v[2]);
  int fd=open(v[1], wr?(O_WRONLY|O_CREAT|O_APPEND):O_RDONLY, 0644);
  if(fd>=0){printf("OPEN_OK\n");close(fd);return 0;}
  printf("OPEN_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/rw" "$WORK/rw.c" || { echo "compile failed"; exit 2; }

# pre-create targets (as the unwatched shell — allowed)
echo "# crontab"      > "$WORK/etc/crontab"
echo "ssh-rsa AAA"    > "$WORK/.ssh/authorized_keys"
echo "alias x=y"      > "$WORK/home/.bashrc"
echo "/evil.so"       > "$WORK/etc/ld.so.preload"
echo "ok"             > "$WORK/normal.txt"

cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
EOF

OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up" "R3 enforcement live" "$(cat "$WORK/out")"

# 1-4 KEY — watched WRITE to persistence locations BLOCKED
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$WORK/etc/crontab" 1 2>&1)
chk "watched WRITE /etc/crontab BLOCKED            «persist leg shut»" "errno=1\(" "$A"
B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$WORK/.ssh/authorized_keys" 1 2>&1)
chk "watched WRITE ~/.ssh/authorized_keys BLOCKED" "errno=1\(" "$B"
C=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$WORK/x/cron.d/evil" 1 2>&1)
chk "watched WRITE /etc/cron.d/evil (new file) BLOCKED" "errno=1\(" "$C"
D=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$WORK/home/.bashrc" 1 2>&1)
chk "watched WRITE ~/.bashrc BLOCKED" "errno=1\(" "$D"

# 5. READ of a persistence file is ALLOWED (R14 guards WRITES only)
E=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$WORK/etc/crontab" 0 2>&1)
chk "watched READ /etc/crontab ALLOWED (writes-only guard)" "OPEN_OK" "$E"

# 6. WRITE to a normal file is ALLOWED (no over-block)
F=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/rw" "$WORK/normal.txt" 1 2>&1)
chk "watched WRITE normal file ALLOWED" "OPEN_OK" "$F"

# 7. UNWATCHED WRITE to a persistence file is ALLOWED (scoping)
G=$("$WORK/rw" "$WORK/etc/crontab" 1 2>&1)
chk "UNWATCHED WRITE /etc/crontab ALLOWED (scoping)" "OPEN_OK" "$G"

echo "===== persistence guard (R14): $pass passed, $fail failed ====="
exit "$fail"
