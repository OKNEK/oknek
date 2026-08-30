#!/usr/bin/env bash
# Container/k8s proof: a watched agent running inside a SEPARATE PID namespace
# (like a container) reports its namespace-local pid, but the daemon registers the
# kernel-translated GLOBAL pid via SO_PEERCRED — so kernel enforcement actually
# matches. Watched sudo inside `unshare --pid` is BLOCKED; the daemon logs the
# nspid->global translation; unwatched in-namespace is not oknek-blocked. Isolated
# pins; prod untouched.
set -u
OKNEKD=/tmp/oknekd-cont; OKNEK=/tmp/oknek-cont; WORK=/tmp/oknek-cont-e2e
PINDIR=/sys/fs/bpf/oknek-conttest; SUDO=$(command -v sudo)
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up" "R3 enforcement live" "$(cat "$WORK/out")"

# host baseline: watched sudo blocked (global==self)
H=$("$OKNEK" --config "$WORK/oknek.yaml" run "$SUDO" -n true 2>&1)
chk "host watched sudo BLOCKED (baseline)" "not permitted" "$H"

# CONTAINER: watched agent inside a NEW pid namespace (nspid != global)
A=$(unshare --pid --fork bash -c "echo nspid=\$\$; $OKNEK --config $WORK/oknek.yaml run $SUDO -n true 2>&1")
echo "--- in-namespace output ---"; echo "$A"
chk "CONTAINERIZED watched sudo BLOCKED  «PID-ns translated via SO_PEERCRED»" "not permitted" "$A"

# the daemon logged the nspid -> global translation (proves it didn't trust the body pid)
T=$(grep -a "container-translated" "$WORK/out" | tail -1)
chk "daemon translated nspid->global pid" "global pid [0-9]+ \(agent-reported nspid" "$T"

# control: UNWATCHED sudo in a namespace is not oknek-blocked
B=$(unshare --pid --fork bash -c "$SUDO -n true; echo rc=\$?")
chk "CONTAINERIZED unwatched sudo not oknek-blocked (scoping)" "rc=0" "$B"

echo "===== container/k8s PID-namespace support: $pass passed, $fail failed ====="
exit "$fail"
