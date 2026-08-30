#!/usr/bin/env bash
# Gated-disarm acceptance — POST-reboot phase. After a reboot, the staged marker must be
# HONORED: the loader records DISARMED and does NOT arm self_guard, so the off-switch is now
# REMOVABLE (clean uninstall). Then re-arm cleanly once the marker is consumed.
set -u
OKNEKD=/root/oknek-local/bin/oknekd
OKNEK=/root/oknek-local/bin/oknek
W=/root/oknek-disarm-drill
PINDIR=/sys/fs/bpf/oknek-disarm
export OKNEK_BPF_PIN_DIR="$PINDIR"
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }

echo "post-reboot: marker present=$([ -f "$W/disarm.marker" ] && echo yes || echo NO) · bpffs($PINDIR)=$(ls "$PINDIR" 2>/dev/null | wc -l) (reboot cleared kernel state)"

echo "=== boot with marker present: loader must NOT arm self_guard ==="
$OKNEKD --config "$W/oknek.yaml" > "$W/out2" 2>&1 & DP=$!
sleep 2
chk "marker HONORED — disarm logged, not arming" "authorized disarm marker honored.*NOT arming" "$(cat "$W/out2")"
if grep -q "self_guard: R20 armed" "$W/out2"; then echo "FAIL: self_guard armed despite valid disarm marker"; fail=$((fail+1)); else echo "PASS: self_guard NOT armed (disarmed)"; pass=$((pass+1)); fi

echo "=== off-switch now REMOVABLE (was EPERM when armed) -> clean uninstall to 0 progs ==="
kill "$DP" 2>/dev/null; sleep 1
RM=$(rm -rf "$PINDIR" 2>&1); RC=$?
if [ "$RC" -eq 0 ] && [ ! -d "$PINDIR" ]; then echo "PASS: pins removable after disarm (rm rc=0) — uninstall to 0 progs possible"; pass=$((pass+1)); else echo "FAIL: rm still blocked post-disarm: $RM"; fail=$((fail+1)); fi
[ -f "$W/disarm.marker" ] && echo "NOTE: marker still present" || { echo "PASS: marker consumed (DISARMED recorded)"; pass=$((pass+1)); }

echo "=== DISARMED paired with DISARM-AUTHORIZED (verify-control) ==="
VC=$($OKNEK --config "$W/oknek.yaml" okular verify 2>&1 | tail -3)
echo "   okular verify: $VC"

echo "=== re-arm cleanly: with no marker, a fresh start arms again ==="
$OKNEKD --config "$W/oknek.yaml" > "$W/out3" 2>&1 & DP=$!
sleep 2
chk "re-arm clean (no marker)" "self_guard: R20 armed.*enforce=true" "$(cat "$W/out3")"
kill "$DP" 2>/dev/null

echo "===== disarm POST-reboot: $pass passed, $fail failed ====="
exit "$fail"
