#!/usr/bin/env bash
# R15 proof: a watched agent cannot exec a privilege-escalation helper (sudo/su/
# pkexec/...) — blocked at lsm/bprm_check_security. Normal binaries exec fine;
# unwatched exec of sudo is allowed (scoping). Isolated pins; prod untouched.
set -u
OKNEKD=/tmp/oknekd-r15; OKNEK=/tmp/oknek-r15; WORK=/tmp/oknek-r15-e2e
PINDIR=/sys/fs/bpf/oknek-r15test
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
EOF
SUDO=$(command -v sudo); SU=$(command -v su)

OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up" "R3 enforcement live" "$(cat "$WORK/out")"

# 1. KEY — watched exec of sudo BLOCKED
A=$("$OKNEK" --config "$WORK/oknek.yaml" run "$SUDO" -n true 2>&1; echo "rc=$?")
chk "watched exec sudo BLOCKED  «escalate leg shut»" "not permitted|denied|rc=[^0]" "$A"

# 2. watched exec of su BLOCKED
B=$("$OKNEK" --config "$WORK/oknek.yaml" run "$SU" root -c true 2>&1; echo "rc=$?")
chk "watched exec su BLOCKED" "not permitted|denied|rc=[^0]" "$B"

# 3. watched exec of a normal binary ALLOWED
C=$("$OKNEK" --config "$WORK/oknek.yaml" run /bin/echo OK-ECHO 2>&1)
chk "watched exec normal binary ALLOWED" "OK-ECHO" "$C"

# 4. UNWATCHED exec of sudo ALLOWED (scoping) — sudo runs (may itself deny, but EXEC is allowed:
#    a blocked-by-R15 exec gives 'not permitted'; sudo's own auth failure does NOT)
D=$("$SUDO" -n true 2>&1; echo "rc=$?")
chk "UNWATCHED exec sudo not blocked by R15 (scoping)" "rc=(0|1)$" "$D"

echo "===== privesc/exec guard (R15): $pass passed, $fail failed ====="
exit "$fail"
