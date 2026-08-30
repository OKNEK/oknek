#!/usr/bin/env bash
# Class 6 (honest-coverage half): `oknek doctor` reports the TRUE enforcement
# posture. ENFORCING config -> KERNEL-ENFORCED + 5/5 pins; observe config ->
# OBSERVE. (DEGRADED is the !bpf-lsm branch; this box HAS bpf-lsm so that path
# can't be exercised here.) Isolated; prod untouched; cleaned up.
set -u
OKNEKD=/tmp/oknekd-inode; OKNEK=/tmp/oknek-inode; WORK=/tmp/oknek-doc-e2e
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2]"; echo "$3" | sed 's/^/      /'; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ] && kill $DP 2>/dev/null; rm -rf /sys/fs/bpf/oknek 2>/dev/null' EXIT
rm -rf /sys/fs/bpf/oknek 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
echo "top-secret" > "$WORK/secret"

mkcfg(){ cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
protected_files:
  - $WORK/secret
egress_jail:
  enabled: true
  gateway: { host: "127.0.0.1", port: 4000 }
  enforce: $1
EOF
}

# ---- posture A: ENFORCING ----
mkcfg true
"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
A=$("$OKNEK" --config "$WORK/oknek.yaml" doctor 2>&1)
echo "$A"
chk "enforcing: verdict KERNEL-ENFORCED" "KERNEL-ENFORCED" "$A"
chk "enforcing: 5/5 links pinned"        "5/5" "$A"
chk "enforcing: kernel BPF-LSM active"   "kernel BPF-LSM active" "$A"
chk "enforcing: egress ENFORCING"        "ENFORCING" "$A"
chk "enforcing: 1 protected cred file"   "1 file" "$A"
chk "enforcing: host PID ns (not containerized)" "host PID namespace" "$A"
kill $DP 2>/dev/null; wait $DP 2>/dev/null; DP=""; rm -rf /sys/fs/bpf/oknek 2>/dev/null
echo "------------------------------------------"

# ---- posture B: OBSERVE ----
mkcfg false
"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out2" 2>&1 & DP=$!
sleep 1.8
B=$("$OKNEK" --config "$WORK/oknek.yaml" doctor 2>&1)
echo "$B"
chk "observe: verdict OBSERVE"           "OBSERVE" "$B"
chk "observe: egress shows observe"      "egress jail .R11. +observe" "$B"
chk "observe: warns to set enforce true" "set egress_jail.enforce" "$B"

echo "===== oknek doctor (Class 6 preflight): $pass passed, $fail failed ====="
exit "$fail"
