#!/usr/bin/env bash
# R18 (kernel-module-load) + R19 (mount) anti-rootkit/anti-escape guards. A watched
# agent can't load a kernel module (finit_module->kernel_read_file READING_MODULE)
# or mount/remount (sb_mount). Unwatched mount works (scoping). Isolated pins; prod
# untouched; no module is actually loaded on the box (we assert the block + that
# lsmod stays clean).
set -u
OKNEKD=/tmp/oknekd-km; OKNEK=/tmp/oknek-km; WORK=/tmp/oknek-km-e2e
PINDIR=/sys/fs/bpf/oknek-kmtest
pass=0; fail=0
chk(){ if echo "$3"|grep -qiE "$2"; then echo "PASS: $1"; echo "   |- $3"; pass=$((pass+1)); else echo "FAIL: $1 -- want[$2] got[$3]"; fail=$((fail+1)); fi; }
DP=""; trap '[ -n "$DP" ]&&kill $DP 2>/dev/null; rmmod oknek_dummy 2>/dev/null; rmmod dummy 2>/dev/null; umount /tmp/r19b 2>/dev/null; rmdir /tmp/r19a /tmp/r19b 2>/dev/null; rm -rf "$PINDIR" 2>/dev/null' EXIT
rm -rf "$PINDIR" 2>/dev/null; rm -rf "$WORK"; mkdir -p "$WORK/rules/active" /tmp/r19a /tmp/r19b
cat > "$WORK/oknek.yaml" <<EOF
socket: $WORK/oknek.sock
db_path: $WORK/oknek.db
log_path: $WORK/oknek.log
rules_dir: $WORK/rules/active
EOF
OKNEK_BPF_PIN_DIR="$PINDIR" "$OKNEKD" --config "$WORK/oknek.yaml" > "$WORK/out" 2>&1 & DP=$!
sleep 1.8
chk "daemon up" "R3 enforcement live" "$(cat "$WORK/out")"

# ---- R18 kernel-module-load guard (watched finit_module/insmod -> EPERM, by effect) ----
# Turnkey capture: use an in-tree throwaway module if present, else BUILD a trivial one so
# the drill no longer self-skips. Needs linux-headers-$(uname -r) + make (the box provision
# recipe installs both). Modern insmod/modprobe use finit_module(2) -> kernel_read_file with
# READING_MODULE, which is exactly what R18 hooks. STAGED-UNVERIFIED off-box: the .ko build
# and insmod paths only run on a BPF-LSM Linux box; not exercised on macOS.
MODNAME=""; MODKO=""
rmmod oknek_dummy 2>/dev/null; rmmod dummy 2>/dev/null
if modinfo dummy >/dev/null 2>&1; then
  MODNAME=dummy
  A=$("$OKNEK" --config "$WORK/oknek.yaml" run modprobe dummy 2>&1; echo "rc=$?")
else
  MB="$WORK/mod"; mkdir -p "$MB"
  cat > "$MB/oknek_dummy.c" <<'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
static int __init oknek_dummy_init(void){ pr_info("oknek_dummy: loaded\n"); return 0; }
static void __exit oknek_dummy_exit(void){ pr_info("oknek_dummy: unloaded\n"); }
module_init(oknek_dummy_init);
module_exit(oknek_dummy_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("oknek R18 drill throwaway module");
EOF
  printf 'obj-m += oknek_dummy.o\nall:\n\t$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules\n' > "$MB/Makefile"
  if command -v make >/dev/null 2>&1 && make -C "$MB" > "$WORK/modbuild.log" 2>&1; then
    MODNAME=oknek_dummy; MODKO="$MB/oknek_dummy.ko"; rmmod oknek_dummy 2>/dev/null
    A=$("$OKNEK" --config "$WORK/oknek.yaml" run insmod "$MODKO" 2>&1; echo "rc=$?")
  else
    echo "SKIP: no in-tree 'dummy' and module build failed (need linux-headers-$(uname -r)); R18 hook attached but NOT drilled. See $WORK/modbuild.log"
  fi
fi
if [ -n "$MODNAME" ]; then
  # (1) watched load BLOCKED, by effect
  chk "watched insmod/modprobe BLOCKED  «kernel rootkit shut»" "not permitted|could not insert|denied|operation not permitted|rc=[^0]" "$A"
  L=$(lsmod | grep -c "^$MODNAME ")
  chk "module did NOT load (block real — lsmod clean)" "^0$" "$L"
  # (2) NEGATIVE-SCOPE: an UNWATCHED process still loads modules normally. R18 is watched-only;
  #     the host's own module loading must not be bricked.
  if [ -n "$MODKO" ]; then U=$(insmod "$MODKO" 2>&1; echo "rc=$?"); else U=$(modprobe "$MODNAME" 2>&1; echo "rc=$?"); fi
  chk "UNWATCHED load ALLOWED (scoping — host not bricked)" "rc=0" "$U"
  UL=$(lsmod | grep -c "^$MODNAME ")
  chk "unwatched load actually took effect (lsmod shows it)" "^1$" "$UL"
  rmmod "$MODNAME" 2>/dev/null
fi

# ---- R19 mount guard ----
B=$("$OKNEK" --config "$WORK/oknek.yaml" run mount -t tmpfs none /tmp/r19a 2>&1; echo "rc=$?")
chk "watched mount BLOCKED  «mount-escape shut»" "not permitted|denied|rc=[^0]" "$B"
C=$(mount -t tmpfs none /tmp/r19b 2>&1; echo "rc=$?"); umount /tmp/r19b 2>/dev/null
chk "UNWATCHED mount ALLOWED (scoping)" "rc=0" "$C"

echo "===== R18 kmod + R19 mount: $pass passed, $fail failed ====="
exit "$fail"
