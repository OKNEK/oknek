#!/usr/bin/env bash
# Class 4 proof: R3 now matches protected creds by (dev, inode), so opening the
# same file through a HARDLINK or a RENAME (different path, same inode) is BLOCKED
# — the name-only evasion is shut. Name-based R3 still fires (regression); the
# block is scoped to watched agents (unwatched allowed); unprotected files allowed.
# Isolated; prod untouched; cleaned up.
set -u
OKNEKD=/tmp/oknekd-inode; OKNEK=/tmp/oknek-inode; WORK=/tmp/oknek-inode-e2e
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf /sys/fs/bpf/oknek 2>/dev/null' EXIT
rm -rf /sys/fs/bpf/oknek 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active" "$WORK/.aws"

# reader helper: open(path, O_RDONLY) -> OPEN_OK / OPEN_BLOCKED errno=N
cat > "$WORK/reader.c" <<'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
int main(int c,char**v){
  int fd=open(v[1],O_RDONLY);
  if(fd>=0){printf("OPEN_OK\n");close(fd);return 0;}
  printf("OPEN_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/reader" "$WORK/reader.c" || { echo "compile failed"; exit 2; }

# the protected secret + an innocent file + a name-pattern cred (.aws/credentials)
echo "top-secret-key" > "$WORK/secret"
echo "hello"          > "$WORK/innocent"
echo "AKIA-fake"      > "$WORK/.aws/credentials"

cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
protected_files:
  - $WORK/secret
EOF

"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon loaded protected inode" "cred_guard: 1 protected inode" "$(cat "$WORK/out")"

# Agent creates evasion paths AT RUNTIME (after the inode was loaded):
ln "$WORK/secret" "$WORK/hard"      # hardlink — same inode, different name
ln "$WORK/secret" "$WORK/hard2"; mv "$WORK/hard2" "$WORK/renamed"  # rename a link

# 1. SANITY — watched agent opening the protected file directly is BLOCKED (inode path live)
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/reader" "$WORK/secret" 2>&1)
chk "watched open of protected secret BLOCKED" "errno=1\(" "$A"

# 2. KEY — watched agent opening it via a HARDLINK is BLOCKED (name differs, inode same)
B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/reader" "$WORK/hard" 2>&1)
chk "watched open via HARDLINK BLOCKED  «rename/hardlink evasion shut»" "errno=1\(" "$B"

# 3. KEY — watched agent opening it via a RENAMED link is BLOCKED (same inode)
C=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/reader" "$WORK/renamed" 2>&1)
chk "watched open via RENAMED path BLOCKED" "errno=1\(" "$C"

# 4. regression — name-based R3 (.aws/credentials) still fires
D=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/reader" "$WORK/.aws/credentials" 2>&1)
chk "regression: name-based R3 (.aws/credentials) BLOCKED (shim EACCES first; kernel EPERM for static)" "errno=(1|13)\(" "$D"

# 5. scoping — UNWATCHED process opening the protected inode is ALLOWED
E=$("$WORK/reader" "$WORK/secret" 2>&1)
chk "UNWATCHED open of protected inode ALLOWED (scoping)" "OPEN_OK" "$E"

# 6. no over-block — watched agent opening an unprotected file is ALLOWED
F=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/reader" "$WORK/innocent" 2>&1)
chk "watched open of unprotected file ALLOWED" "OPEN_OK" "$F"

echo "===== inode-matching (Class 4): $pass passed, $fail failed ====="
exit "$fail"
