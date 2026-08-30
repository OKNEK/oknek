# oknek

> **Rogue agents can't escape the kernel.**
> Runtime security for AI agents, enforced below the agent with BPF-LSM — plus an audit even root can't scrub.

`oknekd` is a single static Go daemon that attaches eBPF **BPF-LSM** programs at the Linux kernel's security hooks and enforces a **default-deny policy on a watched AI-agent process and every child it spawns**. Claude Code, Cursor, Codex, an MCP server, a cron'd agent — whatever you run under `oknek run` can no longer read your credentials, reach a destination you didn't allow, persist itself, escalate, open a backdoor, tamper with its own skills, or switch oknek off. Every verdict is sealed into **Okular**, a hash-chained, ed25519-signed, anchored ledger.

It is not a prompt firewall, not a model scanner, not a network gateway. It sits in one seat nobody else occupies: *inside the host, beneath the agent, where the agent cannot reach.*

```
$ oknek run --agent claude-code --profile dev -- cat ~/.aws/credentials
cat: /root/.aws/credentials: Operation not permitted        # R3, in-kernel, before the syscall runs

$ kill -9 $(pidof oknekd); oknek run --agent claude-code -- cat ~/.aws/credentials
cat: /root/.aws/credentials: Operation not permitted        # links are pinned: enforcement outlives the daemon
```

Runs in production on our own hosts since May 2026 (Ubuntu 24.04, kernel 6.8). Accepted into Anthropic's Cyber Verification Program. **AGPL-3.0.**

---

## Quickstart (5 minutes, Linux)

**Requirements:** Linux ≥ 5.8 with the `bpf` LSM active, Go ≥ 1.22, a C compiler (for the userspace shim). Ubuntu 24.04 ships everything.

```sh
# 1. is BPF-LSM on?  (must list "bpf")
cat /sys/kernel/security/lsm
#    if not: add bpf to GRUB_CMDLINE_LINUX in /etc/default/grub, e.g.
#    lsm=lockdown,capability,landlock,yama,apparmor,bpf   → update-grub → reboot

# 2. build
git clone https://github.com/oknek/oknek && cd oknek
make build          # bin/oknekd  bin/oknek     (the BPF object is prebuilt + embedded)
make shim-linux     # dist/liboknek_preload.so  (userspace fallback / hostname attribution)

# 3. install + start
sudo install -m0755 bin/oknekd bin/oknek /usr/local/bin/
sudo install -d /usr/local/lib/oknek && sudo install -m0644 dist/liboknek_preload.so /usr/local/lib/oknek/
sudo install -d /etc/oknek && sudo cp deploy/oknek.oss.yaml /etc/oknek/oknek.yaml
sudo install -m0644 systemd/oknekd.service /etc/systemd/system/ && sudo systemctl enable --now oknekd

# 4. prove it
oknek doctor                                   # want: 🟢 KERNEL-ENFORCED, 14/14 links pinned
oknek run --agent test -- cat ~/.aws/credentials   # want: Operation not permitted
oknek replay test                              # the block, sealed
```

Then wrap your real agent: `oknek run --agent claude-code --profile dev -- claude`. Start in observe mode (the example config does), read `oknek egress` / `oknek taint` / `oknek mcp` for a day, flip `enforce: true`.

Without BPF-LSM the daemon still runs in `LD_PRELOAD` mode — `doctor` says 🔴 DEGRADED and means it: a static binary can slip past the shim. The kernel path is the product.

---

## What it enforces

Scope: **watched agents and their descendants only** (fork-propagated in-kernel; re-parenting to `init` doesn't escape). Your shell, `sshd`, `cron` are never touched. Every deny is `-EPERM` at the LSM hook, before the syscall runs.

| Leg | Rules | What a rogue agent can no longer do |
|---|---|---|
| **Steal** | R3 · R13 | read credential files (name patterns + inode match: hardlink/rename/bind-mount proof) · read another process's memory |
| **Exfiltrate** | R11 · R12 | connect anywhere but the gateway + DNS + loopback, TCP, UDP/QUIC, `sendmsg` (per-identity grants via Okredo) · beacon undetected |
| **Persist** | R14 | write cron, `authorized_keys`, `ld.so.preload`, sudoers, passwd, shell rc |
| **Escalate** | R15 | exec sudo / su / pkexec / doas |
| **Backdoor** | R16 | bind a non-loopback listener |
| **Self-defense** | R17 · R18 · R19 · R20 | call `bpf()` · load a kernel module · mount · `rm`/`mv`/`umount` oknek's own pins — and `kill -9 oknekd` leaves enforcement running |
| **Supply chain** | R22 | write a pinned skill / hook / settings / MCP manifest in place; open or exec one the integrity sweep found tampered (quarantine, lifted only by `oknek pin --accept`) |
| **Canary** | R23 | touch a planted decoy credential (alert, or block) |
| **Rule of Two** | R21 | hold all three of *untrusted input · private data · external comms* in one session — the syscall that would grant the third is denied ([Meta, Oct 2025](https://ai.meta.com/blog/practical-ai-agent-security/)) |
| **MCP** | R24 | let an MCP server reach anything beyond its declared grants — each stdio server gets its own kernel identity |

Detection rules R1–R7 (subcommand-chain bypass, settings flips, MCP URL drift, instruction-file injection, behavioral drift) run in userspace alongside.

### The three pillars

- **the `.o`** — 14 BPF-LSM programs (`internal/hooks/ebpf/oknek_lsm.c`). Enforce.
- **Okredo** — per-agent identity → authorization. `oknek run --profile <name>` binds an agent to a profile; same destination, different identity, different verdict. **Okredo Attest** mints a 5-minute EdDSA JWT (JWT-SVID-shaped, `spiffe://oknek/<install>/host/<h>/agent/<a>`) carrying the enforcement posture, the audit anchor and the session taint — an agent identity issued by the enforcer beneath the agent, not a token the agent holds. `oknek identity issue|verify|pubkey`.
- **Okular** — append-only, hash-chained, ed25519-signed ledger with anchored checkpoints and signed offline export. `oknek okular`, `oknek replay <agent>`, `oknek okular export`. You can stop enforcement out-of-band (reboot, kernel exploit) — you cannot do it quietly: the silence leaves an un-backfillable gap.

---

## Honest limits

`oknek doctor` reports the true posture; the daemon cannot claim coverage it doesn't have. Read [`docs/public/THREAT-MODEL.md`](docs/public/THREAT-MODEL.md) before trusting it with anything. Short version:

- Out of band, cannot be prevented, is made loud: reboot without the `bpf` LSM, kernel exploit, the boot race before attach.
- Content inside an allowed TLS connection is invisible — that's your gateway's job.
- A daemon inside a container covers only its own PID namespace. Run it on the host.
- `LD_PRELOAD` mode cannot see a static or env-scrubbed child. Kernel mode can.
- R22 write-deny catches in-place writes; an editor-style atomic replace is caught by the sweep, not at the instant of the rename.
- R21 directory matching is one level deep; by default an allowed external connect counts as both untrusted input and external comms (`rule_of_two.network_trusted: true` for pure Rule-of-Two semantics).

## Layout

```
cmd/oknekd            daemon        cmd/oknek           CLI
internal/hooks/ebpf   BPF-LSM programs + loader (the .o)
internal/hooks/preload  LD_PRELOAD shim (fallback + hostname attribution)
internal/okular       audit ledger  internal/identity   Okredo Attest (JWT)
internal/pins         R22           internal/canary     R23         internal/mcp   R24 manifests
internal/rules        R1–R7 detection engine            tests/e2e   hardware proofs (one script per rule)
deploy/oknek.oss.yaml example config · systemd/oknekd.service · docs/public/THREAT-MODEL.md
```

Every kernel rule ships with an e2e script under `tests/e2e/` that runs an isolated daemon (own bpffs pin dir, own socket/db) with positive, negative and unwatched-control cases. `make test` runs the Go suite; the e2e scripts need a BPF-LSM box.

## Licensing

**AGPL-3.0.** See [`LICENSE`](./LICENSE). The daemon, CLI, rule packs and BPF programs are source-readable so you can audit exactly what runs as root on your host, and any redistributed modification must stay open. The oknek.com control plane (multi-host dashboard, Dean, WORM audit escrow) is proprietary and sold per host: [oknek.com/pricing](https://oknek.com/pricing/).

## Security

To report a vulnerability, email `security@oknek.com`. We acknowledge within 48 hours, triage within 5 business days, and ship a fix within 30 days for high-severity findings. See `/.well-known/security.txt` on oknek.com.

## Links

- [oknek.com](https://oknek.com) · [threats](https://oknek.com/threats/) · [docs](https://oknek.com/docs/) · [pricing](https://oknek.com/pricing/)
