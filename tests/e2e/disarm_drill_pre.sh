#!/usr/bin/env bash
# Gated-disarm acceptance — PRE-reboot phase. Proves: self_guard arms; a FORGED / EXPIRED /
# WRONG-HOST token is DENIED (no marker staged); a VALID off-box-signed token is AUTHORIZED,
# recorded record-first, and stages a disarm-on-boot marker. Persistent workdir under /root
# so the marker + okular ledger survive the reboot for the POST phase.
set -u
OKNEKD=/root/oknek-local/bin/oknekd
OKNEK=/root/oknek-local/bin/oknek
W=/root/oknek-disarm-drill
PINDIR=/sys/fs/bpf/oknek-disarm
export OKNEK_BPF_PIN_DIR="$PINDIR"
HOST=$(hostname)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }

if [ -d "$PINDIR" ] && ! rm -rf "$PINDIR" 2>/dev/null; then
  echo "ABORT: $PINDIR holds a live enforce guard — reboot first"; exit 2; fi
rm -rf "$W"; mkdir -p "$W/rules/active"

echo "=== off-box keypairs (real + attacker) ==="
$OKNEK disarm keygen > "$W/k1.txt" 2>&1
PUB1=$(grep -oE '\b[0-9a-f]{64}\b' "$W/k1.txt" | head -1)
PRIV1=$(grep -oE '\b[0-9a-f]{128}\b' "$W/k1.txt" | head -1)
$OKNEK disarm keygen > "$W/k2.txt" 2>&1
PRIV2=$(grep -oE '\b[0-9a-f]{128}\b' "$W/k2.txt" | head -1)
echo "host=$HOST  pub1=${PUB1:0:20}…  (priv1/priv2 generated)"
[ -z "$PUB1" ] || [ -z "$PRIV1" ] || [ -z "$PRIV2" ] && { echo "FAIL: keygen parse"; exit 2; }

cat > "$W/oknek.yaml" <<EOF
socket: $W/oknek.sock
db_path: $W/oknek.db
log_path: $W/oknek.log
rules_dir: $W/rules/active
okular:
  enabled: true
  path: $W/okular.db
self_guard:
  enabled: true
  enforce: true
disarm:
  enabled: true
  pub_key: $PUB1
  marker_path: $W/disarm.marker
EOF

$OKNEKD --config "$W/oknek.yaml" > "$W/out" 2>&1 & DP=$!
sleep 2
chk "self_guard armed (enforce)" "self_guard: R20 armed.*enforce=true" "$(cat "$W/out")"

echo "=== FORGED token (attacker key) -> DENIED, no marker ==="
$OKNEK --config "$W/oknek.yaml" disarm sign --key "$PRIV2" --host "$HOST" --ttl 1h > "$W/forged.json" 2>"$W/e"
F=$($OKNEK --config "$W/oknek.yaml" disarm request --token "$W/forged.json" 2>&1)
chk "FORGED token DENIED (bad signature)" "DENIED|bad.*signature" "$F"
[ -f "$W/disarm.marker" ] && { echo "FAIL: marker staged for forged token"; fail=$((fail+1)); } || { echo "PASS: no marker for forged token"; pass=$((pass+1)); }

echo "=== EXPIRED token (real key, past expiry) -> DENIED ==="
$OKNEK --config "$W/oknek.yaml" disarm sign --key "$PRIV1" --host "$HOST" --ttl=-1h > "$W/expired.json" 2>"$W/e"
E=$($OKNEK --config "$W/oknek.yaml" disarm request --token "$W/expired.json" 2>&1)
chk "EXPIRED token DENIED" "DENIED|expired" "$E"

echo "=== WRONG-HOST token (real key, other host) -> DENIED ==="
$OKNEK --config "$W/oknek.yaml" disarm sign --key "$PRIV1" --host "not-this-box" --ttl 1h > "$W/wrong.json" 2>"$W/e"
WH=$($OKNEK --config "$W/oknek.yaml" disarm request --token "$W/wrong.json" 2>&1)
chk "WRONG-HOST token DENIED" "DENIED|not bound" "$WH"

echo "=== VALID token -> AUTHORIZED + marker staged ==="
$OKNEK --config "$W/oknek.yaml" disarm sign --key "$PRIV1" --host "$HOST" --ttl 1h > "$W/valid.json" 2>"$W/e"
V=$($OKNEK --config "$W/oknek.yaml" disarm request --token "$W/valid.json" 2>&1)
chk "VALID token AUTHORIZED (reboot to complete)" "OK|REBOOT|AUTHORIZED" "$V"
[ -f "$W/disarm.marker" ] && { echo "PASS: disarm-on-boot marker staged"; pass=$((pass+1)); } || { echo "FAIL: no marker after valid token"; fail=$((fail+1)); }

kill "$DP" 2>/dev/null
echo "===== disarm PRE-reboot: $pass passed, $fail failed ====="
echo "NEXT: reboot, then bash tests/e2e/disarm_drill_post.sh"
exit "$fail"
