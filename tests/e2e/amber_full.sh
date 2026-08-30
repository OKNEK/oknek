#!/usr/bin/env bash
# AMBER-promotion drill — re-prove map-write / link-detach / kill-persist on the SHIPPED
# 14-prog binary, by effect, so the three SCORECARD rows move 13-prog-AMBER -> 14-prog-GREEN.
#
# Arms BOTH self_guard (freezes oknek_self_id) AND egress_jail (freezes oknek_egress) so the
# map-write vector is tested against both frozen policy maps. REQUIRES A FRESH BOOT (an armed
# enforce guard's pins persist and can't be removed in-band — a prior run contaminates this).
#
#   map-write  : root `bpftool map update` of a frozen policy map -> EPERM (Freeze, by effect)
#   link-detach: root `bpftool link detach` of an LSM link        -> unsupported (kernel)
#   kill-persist: SIGKILL the daemon; pins survive, rm still EPERM, map-write still EPERM
set -u
OKNEKD=/root/oknek-local/bin/oknekd
OKNEK=/root/oknek-local/bin/oknek
WORK=/tmp/oknek-amber; PINDIR=/sys/fs/bpf/oknek-amber
export OKNEK_BPF_PIN_DIR="$PINDIR"
CC=$(command -v cc || command -v gcc || command -v clang)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
mapid(){ bpftool map show 2>/dev/null | awk -v n="name $1 " '$0 ~ n {gsub(/:/,"",$1); print $1; exit}'; }
mapwrite(){ # $1=id ; build correctly-sized zero key+value, attempt userspace update
  local id=$1 info ks vs k v
  info=$(bpftool map show id "$id" 2>/dev/null)
  ks=$(echo "$info" | grep -oE 'key [0-9]+' | grep -oE '[0-9]+'); vs=$(echo "$info" | grep -oE 'value [0-9]+' | grep -oE '[0-9]+')
  k=$(printf '0 %.0s' $(seq 1 "${ks:-4}")); v=$(printf '0 %.0s' $(seq 1 "${vs:-8}"))
  bpftool map update id "$id" key $k value $v 2>&1; }

echo "AMBER promotion (comprehensive) — 14-prog shipped binary"
echo "  $(date -u +%FT%TZ) · kernel $(uname -r) · lsm=$(cat /sys/kernel/security/lsm)"
if [ -d "$PINDIR" ] && ! rm -rf "$PINDIR" 2>/dev/null; then
  echo "ABORT: $PINDIR holds a live enforce guard — reboot first"; exit 2; fi
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
egress_jail:
  enabled: true
  enforce: true
self_guard:
  enabled: true
  enforce: true
EOF
"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 2
chk "self_guard R20 armed (enforce)" "self_guard: R20 armed.*enforce=true" "$(cat "$WORK/out")"
echo "   egress-jail log: $(grep -iE 'egress' "$WORK/out" | head -1)"
echo

echo "### map-write: frozen policy maps reject root userspace write (Freeze, by effect) ###"
for NM in oknek_self_id oknek_egress; do
  ID=$(mapid "$NM"); FL=$(bpftool map show id "$ID" 2>/dev/null | grep -oE 'flags 0x[0-9a-f]+')
  W=$(mapwrite "$ID")
  chk "map-write to frozen $NM (id $ID, $FL) BLOCKED" "not permitted|frozen|read.?only|denied" "$W"
done; echo

echo "### link-detach: LSM link is non-detachable (kernel unsupported) ###"
LID=$(bpftool link show 2>/dev/null | awk '/^[0-9]+:/{gsub(/:/,"",$1); id=$1} /prog_type lsm/{print id; exit}')
D=$(bpftool link detach id "$LID" 2>&1)
chk "link-detach of LSM link id $LID UNSUPPORTED" "not supported|EOPNOTSUPP|not permitted|invalid argument|failed|cannot" "$D"; echo

echo "### kill-persist: SIGKILL the daemon; enforcement survives ###"
PINS=$(ls "$PINDIR" 2>/dev/null | wc -l)
kill -9 "$DP" 2>/dev/null; sleep 1
[ ! -d "/proc/$DP" ] && { echo "PASS: daemon (pid $DP) is dead"; pass=$((pass+1)); } || { echo "FAIL: daemon still alive"; fail=$((fail+1)); }
PINS2=$(ls "$PINDIR" 2>/dev/null | wc -l)
chk "pins survive SIGKILL ($PINS -> $PINS2)" "[1-9]" "$PINS2 pins remain"
PIN=$(ls "$PINDIR" 2>/dev/null | head -1); RM=$(rm "$PINDIR/$PIN" 2>&1)
chk "rm of pin BLOCKED with daemon dead" "operation not permitted" "$RM"
SID=$(mapid oknek_self_id); W=$(mapwrite "$SID")
chk "self_id map-write STILL blocked with daemon dead" "not permitted|frozen" "$W"
echo
echo "===== AMBER comprehensive: $pass passed, $fail failed ====="
exit "$fail"
