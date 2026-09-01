# Security Policy

oknek runs as root and enforces in the kernel. A flaw here is not a bug in an
app — it is a hole under everything the host runs. Report it privately.

## Reporting a vulnerability

**Preferred:** [open a private security advisory][advisory] on this repository.
It is encrypted, tracked, and does not depend on our mail routing.

**Or:** email `security@oknek.com` (also published at
[`/.well-known/security.txt`](https://oknek.com/.well-known/security.txt)).

Please do not open a public issue, PR, or discussion for a vulnerability.

[advisory]: https://github.com/oknek/oknek/security/advisories/new

**What helps:** the `oknek doctor` output, kernel version and LSM list
(`cat /sys/kernel/security/lsm`), your `/etc/oknek/oknek.yaml` with secrets
redacted, and the smallest reproducer you can manage — ideally shaped like the
scripts in `tests/e2e/`, which run an isolated daemon with its own bpffs pin
dir, socket and database.

## What we commit to

- **Acknowledge within 48 hours.**
- **Triage within 5 business days**, with a severity call and a rough timeline.
- **Fix high-severity findings within 30 days**, or tell you why not.
- Credit in the release notes and at
  [oknek.com/company/security](https://oknek.com/company/security/) if you want it.

We coordinate disclosure: publish 90 days after the report, or on the fix,
whichever comes first — earlier if you prefer and a fix is out.

There is no paid bug bounty. We would rather say so than imply one.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.9.x | ✅ current |
| < 0.9 | ❌ upgrade |

Pre-1.0: fixes land on `main` and in the next tagged release. There are no
backport branches yet.

## In scope

Anything that breaks a guarantee the daemon actually claims:

- **Escaping the watched set** — a descendant of a watched agent that is not
  enforced against (fork, exec, re-parent to `init`, namespace tricks).
- **Defeating an enforced rule** while `oknek doctor` still reports
  `KERNEL-ENFORCED` — reading a protected credential (R3), reaching a
  destination outside the Okredo grant (R11/R12), persistence (R14),
  escalation (R15), a bound listener (R16).
- **Turning enforcement off quietly** — unpinning, detaching or disarming
  (R17–R20) without `doctor` degrading and without the ledger showing a gap.
- **Ledger integrity** — forging, reordering, deleting or backfilling an
  Okular entry so the chain still verifies; a signed export that verifies
  against tampered content.
- **Identity forgery** — minting or altering an Okredo Attest token that
  `oknek identity verify` accepts, or claiming a posture the host is not in.
- **Privilege escalation via oknek itself** — the socket, the SQLite store,
  the config, the installer, or the LD_PRELOAD shim.

## Out of scope

These are documented limits, not vulnerabilities. See
[`docs/public/THREAT-MODEL.md`](docs/public/THREAT-MODEL.md).

- **Root before oknek.** An attacker who is already root on the host before the
  daemon attaches is outside the model.
- **`LD_PRELOAD` (DEGRADED) mode being bypassed.** A static or env-scrubbed
  binary slips the shim by design — `doctor` says 🔴 DEGRADED and means it.
  The kernel path is the product.
- **Booting without the `bpf` LSM, a kernel exploit, the boot race before
  attach.** Out of band, cannot be prevented — made loud, not stopped. The
  un-backfillable ledger gap is the intended outcome, not a bug.
- **Content inside an allowed TLS connection.** That is your gateway's job.
- **A daemon inside a container not covering the host.** It covers its own PID
  namespace; run it on the host.
- **R22 atomic replace** caught by the sweep rather than at the instant of the
  rename, and **R21 one-level directory matching** — both stated in the README.
- Findings against `oknek.com` (the marketing site and control plane) rather
  than this daemon — still welcome at `security@oknek.com`, just not this repo.
