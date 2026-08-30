#!/usr/bin/env bash
# R20 Part C proof: attestation heartbeat = "silence is the alarm". The daemon seals
# a hash-chained heartbeat into Okular every H seconds. A disable we CANNOT prevent
# in-kernel (reboot, kernel exploit, boot-race) stops the beats — and because the
# ledger is append-only + anchored, that silence leaves an un-backfillable gap.
#
#   - CONTINUOUS : while the daemon runs, `oknek attest` reports no gap.
#   - GAP        : stop the daemon (enforcement dark) past the tolerance, restart,
#                  and `oknek attest` reports the silence gap it can't hide.
#
# ISOLATED pin dir; prod untouched. Run on a BPF-LSM box. Uses a short heartbeat
# (2s) + gap_multiple 2 so the test runs in ~20s instead of minutes.
set -u
OKNEKD=/tmp/oknekd-attest; OKNEK=/tmp/oknek-attest; WORK=/tmp/oknek-attest-e2e
PINDIR=/sys/fs/bpf/oknek-attesttest
export OKNEK_BPF_PIN_DIR="$PINDIR"
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
detach_oknek_links(){ bpftool link show 2>/dev/null | sed -n 's/^\([0-9]\+\):.*/\1/p' | while read -r id; do bpftool link detach id "$id" 2>/dev/null || true; done; }
DP=""
cleanup(){ [ -n "$DP" ] && kill "$DP" 2>/dev/null; detach_oknek_links; rm -rf "$PINDIR" "$WORK" 2>/dev/null; }
trap cleanup EXIT
detach_oknek_links; rm -rf "$PINDIR" "$WORK" 2>/dev/null
mkdir -p "$WORK/rules/active"

cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
okular:
  enabled: true
  path: $WORK/okular.db
self_guard:
  enabled: true
  enforce: true
  heartbeat_seconds: 2
  gap_multiple: 2
EOF

# Phase 1 — run long enough for several heartbeats, then attest -> CONTINUOUS.
"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 9
chk "heartbeat attestation started" "attestation heartbeat every 2s" "$(cat "$WORK/out")"
A=$("$OKNEK" --config "$WORK/oknek.yaml" attest 2>&1)
chk "attest CONTINUOUS while enforcement is live" "CONTINUOUS" "$A"

# Phase 2 — kill the daemon (enforcement goes dark) for > tolerance (2*2=4s), then
# restart. The Okular ledger resumes its chain; the silence is now a visible gap.
kill "$DP" 2>/dev/null; DP=""
sleep 7   # > gap tolerance (4s): this window has NO heartbeats
"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out2" 2>&1 & DP=$!
sleep 5   # let it emit a post-restart beat so the gap is bracketed
B=$("$OKNEK" --config "$WORK/oknek.yaml" attest 2>&1)
chk "attest reports the SILENCE GAP (disable that can't be hidden)" "SILENCE GAP|silent [0-9]+s" "$B"

# the ledger must still be chain-intact across the gap (gap != tamper)
V=$("$OKNEK" --config "$WORK/oknek.yaml" okular 2>&1)
chk "okular chain still intact across the gap (silence != tamper)" "intact|true" "$V"

echo "===== R20 attestation heartbeat: $pass passed, $fail failed ====="
exit "$fail"
