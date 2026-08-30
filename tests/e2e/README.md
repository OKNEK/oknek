# OKNEK end-to-end kernel tests

These are the **on-hardware proofs** behind every enforcement claim — the exact
scripts run against a live BPF-LSM kernel, with their assertions. They are the
evidence behind the red-team matrix (`docs/2026-06-26-red-team-matrix.md`) and the
three-pillar architecture (`docs/2026-06-27-oknek-architecture-three-pillars.md`):
a reviewer (or technical DD partner) can **re-run the proof** instead of taking our
word for it.

## How to run

These exercise real `lsm/*` enforcement, so they need a Linux host with `bpf` in the
active LSM list (`cat /sys/kernel/security/lsm` contains `bpf`). macOS can't run them.

1. Cross-build the daemon + CLI: `GOOS=linux GOARCH=amd64 go build -o oknekd ./cmd/oknekd` (and `oknek`).
2. `scp` them to the box at the `/tmp/oknekd-<suffix>` / `/tmp/oknek-<suffix>` paths each
   script declares at the top (e.g. `e2e_inode.sh` expects `/tmp/oknekd-inode`).
3. Run the script **on the box** as root: `bash e2e_inode.sh`. Exit code 0 = all pass.

Each script is self-isolating: it runs its own daemon with a private socket/db, pins
to an isolated `OKNEK_BPF_PIN_DIR` (so it never touches a prod daemon's pins), and
cleans up on exit. The production daemon is never disturbed.

## What each one proves

| Script | Proves | Pass |
|---|---|---|
| `e2e_sendmsg.sh` | Class 1 — UDP/QUIC egress (`socket_sendmsg`) | 5/5 |
| `e2e_fork.sh` | Class 2 — double-fork / reparent escape (fork-propagation) | 4/4 |
| `e2e_pinfreeze.sh` | Class 3 — survive SIGKILL (pinned links) + frozen map | 5/5 |
| `e2e_inode.sh` | Class 4 — hardlink / rename cred evasion (inode match) | 7/7 |
| `e2e_ptrace.sh` | Class 4 memory lane — `process_vm_readv` / `/proc/pid/{mem,environ}` (R13) | 6/6 |
| `e2e_dns.sh` | Class 5 — `:53` restricted to resolvers | 4/4 |
| `e2e_loopback.sh` | Class 5 — loopback restricted to gateway+DNS (proxy-pivot shut) | 6/6 |
| `e2e_doctor.sh` | Class 6 — honest enforcement preflight (`oknek doctor`) | 9/9 |
| `e2e_container.sh` | Container/k8s — agents identified by SO_PEERCRED global pid | 5/5 |
| `e2e_persist.sh` | R14 — persistence/backdoor write guard (cron, authorized_keys, …) | 8/8 |
| `e2e_exec.sh` | R15 — privilege-escalation guard (sudo/su exec) | 5/5 |
| `e2e_bind.sh` | R16 — inbound-backdoor guard (`socket_bind`) | 4/4 |
| `e2e_bpf.sh` | R17 — kernel-tamper / anti-rootkit (`lsm/bpf`) | 3/3 |
| `e2e_kmod_mount.sh` | R18 module-load + R19 mount guards | 5/5 |
| `e2e_okredo.sh` | Okredo v1 — per-agent identity → authorization (same dest, different verdict) | 6/6 |
| `e2e_okredo_v2.sh` | Okredo v2 — CIDR range grants + policy fork-propagation | 8/8 |
| `e2e_okredo_v3.sh` | Okredo v3 — UDP/QUIC allowlist (`socket_sendmsg`) | 5/5 |
| `e2e_okular.sh` | Okular — hash-chained ledger + tamper detection + replay | 3/3 |
| `e2e_okular_export.sh` | Okular — ed25519 signed export, offline verify, tamper-fail | 3/3 |
| `e2e_anchor.sh` | Okular — anchoring catches a full re-chain that fools internal verify | 4/4 |
| `e2e_selfguard.sh` | R20 anti-unpin — root `rm`/`mv` of own pins blocked + **negative-scope gate** | STAGED (box-pending) |
| `e2e_attest.sh` | R20 Part C — heartbeat continuity; a silenced enforcer leaves an un-backfillable gap | STAGED (box-pending) |
