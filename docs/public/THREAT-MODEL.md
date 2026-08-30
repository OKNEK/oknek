# Oknek threat model

This is the honest version. It says what Oknek enforces, for whom, and what it cannot do.

## What Oknek is

`oknekd` is a single static Go daemon that attaches eBPF **BPF-LSM** programs at the Linux kernel's security hooks and enforces a **default-deny policy on watched AI-agent processes and every descendant they spawn**. Every verdict is appended to **Okular**, a hash-chained, ed25519-signed, anchored ledger. Where BPF-LSM is not available it falls back to an `LD_PRELOAD` shim (weaker — see limits).

Oknek is **not** a prompt firewall, a model scanner, a network gateway, CSPM, SAST, or a general-purpose EDR. It sits in one seat: *below the agent, inside the host*.

## Scope: watched agents only

Enforcement applies to processes registered via `oknek run …` (or attached through the shim) and to their whole process tree (fork-propagated in-kernel; re-parenting to `init` does not escape). Unwatched processes — your shell, `sshd`, `cron` — are never touched. The only exception is **R20 anti-unpin**, which guards Oknek's own bpffs pins against anyone, including root.

## What is enforced (kernel, `-EPERM` before the syscall runs)

| Leg | Rules | Hook(s) |
|---|---|---|
| **Steal** | R3 credential-file read (name patterns + inode match: hardlink/rename/bind-mount proof) · R13 cross-process memory read | `file_open`, `ptrace_access_check` |
| **Exfiltrate** | R11 egress jail: only gateway + DNS-to-resolvers + loopback-to-gateway; TCP, UDP/QUIC, `sendmsg`; CIDR grants per identity (Okredo) | `socket_connect`, `socket_sendmsg` |
| **Persist** | R14 writes to cron, `authorized_keys`, `ld.so.preload`, sudoers, passwd, shell rc | `file_open` (FMODE_WRITE) |
| **Escalate** | R15 exec of sudo/su/pkexec/doas | `bprm_check_security` |
| **Backdoor** | R16 non-loopback listener binds | `socket_bind` |
| **Self-defense** | R17 `bpf()` from a watched agent · R18 kernel-module load · R19 mount · R20 rm/mv/umount of Oknek's own pins | `bpf`, `kernel_read_file`, `sb_mount`, `inode_unlink`, `inode_rename`, `sb_umount` |
| **Supply chain** | R22 in-place write to a pinned skill/hook/settings/MCP manifest; open or exec of an artifact the daemon found tampered (quarantine) | `file_open`, `bprm_check_security` |
| **Canary** | R23 open of a planted decoy credential (alert, or block) | `file_open` |
| **Rule of Two** | R21 the syscall that would give a tree its third property of {untrusted input, private data, external comms} | `file_open`, `socket_connect`, `socket_sendmsg` |

Enforcement survives `kill -9 oknekd`: links are pinned to bpffs and the policy map is frozen. `oknek doctor` prints the true posture (🟢 KERNEL-ENFORCED / 🟡 OBSERVE / 🔴 DEGRADED) — the daemon cannot claim coverage it does not have.

## What is out of band (cannot be prevented, is made loud)

- **Reboot** with `bpf` removed from the LSM list, or a **kernel exploit**, or the **boot race** before the guard attaches. Oknek cannot deny these in-kernel. Because Okular is append-only and anchored, the silence they cause leaves a gap that cannot be back-filled: `oknek attest` reports it. You can stop enforcement; you cannot do it quietly.
- **Content** inside an allowed TLS connection. Oknek sees destinations, not payloads. Use your gateway for content policy.
- **A daemon running inside a container** covers only its own PID namespace. Run it on the host (or as a DaemonSet with the socket mounted into workloads).

## Known limits

- **LD_PRELOAD mode** (no BPF-LSM) cannot see a statically linked or env-scrubbed child. `doctor` reports it as DEGRADED.
- **R22 write-deny** catches in-place writes. An editor-style atomic replace (write temp + rename) is caught by the integrity sweep, within `pins.sweep_seconds`, and then quarantined — not at the instant of the rename.
- **R21 untrusted/private directory matching** is one level deep (direct children of a listed directory). By default an allowed non-gateway connect counts as both untrusted input and external comms — so after private data, no external comms at all (the strict exfil cut). Set `rule_of_two.network_trusted: true` for pure Rule-of-Two semantics (a connect is external comms only). Taint is per agent identity (the whole session, children included); a fresh `oknek run --agent` starts clean and `oknek taint clear` is the sealed human checkpoint.
- **R23 canaries** are only planted where no real file exists; they never overwrite.

## Reporting

`security@oknek.com` · `/.well-known/security.txt` on oknek.com. We acknowledge within 48 hours.
