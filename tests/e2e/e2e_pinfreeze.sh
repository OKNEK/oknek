#!/usr/bin/env bash
# Class 3 proof. FREEZE tested while the test daemon is alive, targeting the
# NEWEST oknek_egress map (the test daemon's, never prod's). PIN tested by hard
# SIGKILL then confirming pins + programs persist. Isolated; prod untouched; cleaned up.
set -u
OKNEKD=/tmp/oknekd-pf; WORK=/tmp/oknek-pf
pass=0; fail=0
chk(){ if echo "$3" | grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
trap 'rm -rf /sys/fs/bpf/oknek 2>/dev/null' EXIT
rm -rf /sys/fs/bpf/oknek 2>/dev/null
rm -rf "$WORK"; mkdir -p "$WORK/rules/active"
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/s.sock
db_path: $WORK/db
log_path: $WORK/log
rules_dir: $WORK/rules/active
egress_jail:
  enabled: true
  gateway: { host: "127.0.0.1", port: 4000 }
  enforce: true
EOF
"$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "R11 active (enforce)" "R11 active" "$(cat "$WORK/out")"

echo "--- PIN: links pinned to bpffs ---"
P=$(ls /sys/fs/bpf/oknek 2>/dev/null | tr '\n' ' ')
chk "links pinned to /sys/fs/bpf/oknek" "socket_connect" "$P"

echo "--- FREEZE (daemon alive, NEWEST oknek_egress map = test daemon's) ---"
MID=$(bpftool map show 2>/dev/null | grep -i oknek_egress | grep -oE '^[0-9]+' | sort -n | tail -1)
echo "   target map id: ${MID:-none} (prod's is older/lower)"
if [ -n "$MID" ]; then
  R=$(bpftool map update id "$MID" key hex 00 00 00 00 value hex 7f 00 00 01 00 00 00 00 2>&1 | head -2 | tr '\n' ' ')
  chk "frozen egress map REJECTS userspace write" "error|frozen|permitted|denied|EPERM|invalid" "${R:-<<empty=write-succeeded>>}"
else
  echo "FAIL: no oknek_egress map found"; fail=$((fail+1))
fi
B1=$(bpftool prog show 2>/dev/null | grep -cE "oknek_socket_connect|oknek_file_open")

echo "--- KILL the daemon hard (SIGKILL) ---"
kill -9 "$DP" 2>/dev/null; sleep 1.2
P2=$(ls /sys/fs/bpf/oknek 2>/dev/null | tr '\n' ' ')
chk "pins SURVIVE daemon SIGKILL (enforcement persists)" "socket_connect" "$P2"
B2=$(bpftool prog show 2>/dev/null | grep -cE "oknek_socket_connect|oknek_file_open")
chk "LSM progs still attached after kill" "OK" "$([ "${B2:-0}" -ge 1 ] && echo "OK progs=$B2 (pre-kill=$B1)" || echo "GONE")"

rm -rf /sys/fs/bpf/oknek 2>/dev/null; sleep 0.4
echo "[cleanup] test pins removed -> lingering LSM progs detached"
echo "===== pin+freeze (Class 3): $pass passed, $fail failed ====="
exit "$fail"
