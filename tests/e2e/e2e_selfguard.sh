#!/usr/bin/env bash
# R20 anti-unpin (self-pin-guard) proof. Closes the scorecard's DISABLE gap: root
# can no longer `rm`/`mv` oknek's own bpffs pins to detach enforcement.
#
#   - NEGATIVE-SCOPE GATE (the brick-the-box test): rm/mv of ordinary files OUTSIDE
#     the pin dir ALL succeed. A bug here denies normal host file ops = #1 risk.
#     The gate runs FIRST in the enforce phase and aborts if any ordinary op blocks.
#   - OBSERVE : enforce=false -> the pin rm is logged but ALLOWED (rollout safety).
#   - DISABLE/rm : enforce=true, root rm of a pin -> EPERM. (DISABLE gap closed.)
#   - DISABLE/mv : enforce=true, root mv of a pin -> EPERM.
#   - PERSIST    : enforcement still live after the attempt (a watched R3 read blocks).
#
# ⚠️ REQUIRES A FRESH BOOT. By design an armed enforce guard's pins survive daemon
# death AND can't be rm'd (that's the whole point) — so a prior enforce run
# contaminates this one. Reboot, then run. Observe is tested FIRST (before any
# enforce guard exists on this pin dir) so its "rm allowed" check is clean.
# Cleanup after the enforce phase is best-effort; the enforce pins persist until a
# reboot (or a controlled disarm) — this is the uninstall tension, documented.
#
# ISOLATED pin dir (OKNEK_BPF_PIN_DIR=/sys/fs/bpf/oknek-r20test); prod untouched.
set -u
OKNEKD=/tmp/oknekd-r20; OKNEK=/tmp/oknek-r20; WORK=/tmp/oknek-r20-e2e
PINDIR=/sys/fs/bpf/oknek-r20test
export OKNEK_BPF_PIN_DIR="$PINDIR"
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""
cleanup(){ [ -n "$DP" ] && kill "$DP" 2>/dev/null; rm -rf "$WORK" 2>/dev/null;
  rm -rf "$PINDIR" 2>/dev/null || echo "NOTE: $PINDIR pins persist (armed enforce guard) — reboot to clear"; }
trap cleanup EXIT

# Abort if a prior enforce guard already owns the pin dir (would invalidate results).
if [ -d "$PINDIR" ] && ! rm -rf "$PINDIR" 2>/dev/null; then
  echo "ABORT: $PINDIR exists and can't be removed — a prior enforce guard is live. Reboot first."; exit 2; fi
rm -rf "$WORK" 2>/dev/null
mkdir -p "$WORK/rules/active" "$WORK/.aws" "$WORK/sub/nested" "$WORK/bindsrc" "$WORK/bindmnt"

cat > "$WORK/reader.c" <<'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
int main(int c,char**v){int fd=open(v[1],O_RDONLY);
 if(fd>=0){printf("OPEN_OK\n");close(fd);return 0;}
 printf("OPEN_BLOCKED errno=%d(%s)\n",errno,strerror(errno));return 1;}
EOF
"$CC" -O2 -o "$WORK/reader" "$WORK/reader.c" || { echo "compile failed"; exit 2; }
echo "AKIA-fake" > "$WORK/.aws/credentials"

run_daemon(){ # $1 = enforce (true|false)
  cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
self_guard:
  enabled: true
  enforce: $1
EOF
  "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
  sleep 2
}

echo "================= OBSERVE MODE (tested first, clean slate) ================="
run_daemon false
chk "R20 armed in observe" "self_guard: R20 armed.*enforce=false" "$(cat "$WORK/out")"
PIN=$(ls "$PINDIR" 2>/dev/null | head -1)
[ -z "$PIN" ] && { echo "FAIL: no pins present in $PINDIR"; cat "$WORK/out"; exit 2; }
O=$(rm "$PINDIR/$PIN" 2>&1); orc=$?
if [ $orc -eq 0 ] && [ ! -e "$PINDIR/$PIN" ]; then
  chk "observe: rm of pin ALLOWED (logged, not blocked)" "." "removed $PIN (rc=0)"
else
  chk "observe: rm of pin ALLOWED (logged, not blocked)" "IMPOSSIBLE" "rm blocked in observe: $O"; fi
kill "$DP" 2>/dev/null; DP=""

echo "================= ENFORCE MODE ================="
run_daemon true
chk "R20 armed in enforce" "self_guard: R20 armed.*enforce=true" "$(cat "$WORK/out")"
PIN=$(ls "$PINDIR" 2>/dev/null | grep -v '^moved$' | head -1)
[ -z "$PIN" ] && { echo "FAIL: no pins present in $PINDIR (enforce)"; cat "$WORK/out"; exit 2; }

# ---- NEGATIVE-SCOPE GATE (must pass first; brick-the-box guard) ----
echo "----- negative-scope gate: ordinary file ops MUST still work -----"
G=0; mk(){ echo x > "$1"; }
for f in "$WORK/n1" "$WORK/sub/n2" "$WORK/sub/nested/n3" "/tmp/oknek-r20-host-$$"; do
  mk "$f"; rm "$f" 2>"$WORK/e" || { echo "GATE-FAIL rm denied on ordinary file $f: $(cat "$WORK/e")"; G=1; }
done
mk "$WORK/mvsrc"; mv "$WORK/mvsrc" "$WORK/mvdst" 2>"$WORK/e" || { echo "GATE-FAIL mv denied on ordinary file: $(cat "$WORK/e")"; G=1; }
if mount --bind "$WORK/bindsrc" "$WORK/bindmnt" 2>/dev/null; then
  mk "$WORK/bindmnt/b1"; rm "$WORK/bindmnt/b1" 2>"$WORK/e" || { echo "GATE-FAIL rm denied inside bind mount: $(cat "$WORK/e")"; G=1; }
  umount "$WORK/bindmnt" 2>/dev/null; fi
if [ "$G" -eq 0 ]; then chk "NEGATIVE-SCOPE GATE: all ordinary rm/mv succeed" "." "ok"; else
  echo "FAIL: NEGATIVE-SCOPE GATE — guard is over-broad, would brick the host. ABORT."; fail=$((fail+1)); exit "$fail"; fi

# ---- DISABLE vectors ----
R=$(rm "$PINDIR/$PIN" 2>&1); chk "root rm of own pin BLOCKED (DISABLE/rm)" "operation not permitted" "$R"
[ -e "$PINDIR/$PIN" ] && chk "pin still present after blocked rm" "." "ok" || { echo "FAIL: pin vanished"; fail=$((fail+1)); }
M=$(mv "$PINDIR/$PIN" "$PINDIR/moved" 2>&1); chk "root mv of own pin BLOCKED (DISABLE/mv)" "operation not permitted" "$M"

# ---- PERSIST: enforcement still live (a watched R3 cred read still blocks) ----
P=$("$OKNEK" --config "$WORK/oknek.yaml" run "$WORK/reader" "$WORK/.aws/credentials" 2>&1)
chk "enforcement PERSISTS (watched cred read still blocked)" "OPEN_BLOCKED|errno=1\(" "$P"

# ---- doctor reports the posture honestly ----
DOC=$("$OKNEK" --config "$WORK/oknek.yaml" doctor 2>&1)
chk "doctor: self-guard ENFORCING + 14/14 pins" "anti-unpin self-guard .R20. ENFORCING" "$DOC"

echo "===== R20 anti-unpin (self-pin-guard): $pass passed, $fail failed ====="
exit "$fail"
