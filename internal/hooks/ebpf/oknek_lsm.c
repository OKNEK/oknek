//go:build ignore

/* oknek_lsm.c — kernel-grade R3 (credential-read) enforcement via BPF-LSM.
 *
 * Hooks lsm/file_open. Enforces ONLY on PIDs registered in oknek_agent_pids
 * (so system processes reading files under /etc are never affected — only watched agents).
 * Matches credential files by exact (parent-dir, basename) pairs — verifier-
 * friendly, no bpf_d_path / sleepable gate needed. On a match: emits an event
 * to a ring buffer and returns -EPERM to block the open before it happens.
 *
 * Why this beats LD_PRELOAD: a statically-linked binary (or one that calls the
 * raw open(2) syscall) bypasses the libc interposer entirely, but the kernel
 * LSM hook still fires — so the credential read is blocked anyway.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define NAME_LEN 64
#define AGENT_LEN 64
#define EPERM 1

struct oknek_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 ppid;
	__u8  rule;     /* 3 = R3 */
	__u8  verdict;  /* 2 = block */
	__u8  category; /* 0 exact, 1 suffix, 2 substring, 3 basename */
	__u8  _pad;
	char  comm[16];
	char  agent_id[AGENT_LEN];
	char  dir[NAME_LEN];
	char  name[NAME_LEN];
	/* R11 socket_connect fields (file_open events leave these zero) */
	__u8  daddr[16]; /* dest IP: v4 in bytes 0..3 (network order), or full v6 */
	__u16 dport;     /* dest port, host order */
	__u8  family;    /* AF_INET=2 / AF_INET6=10 */
};
/* keep the struct in BTF so the Go side can mirror it */
struct oknek_event *_oknek_event_type __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} oknek_events SEC(".maps");

/* PIDs of agents oknek is watching (populated by the daemon on hook.attach). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, char[AGENT_LEN]);
} oknek_agent_pids SEC(".maps");

#define AF_INET 2
#define AF_INET6 10
#define ANCESTRY_MAX 16

/* R11 egress-jail policy, pushed by the loader into the single-entry array. */
struct oknek_egress_policy {
	__u8  gw_v4[4];     /* gateway IPv4 bytes (network order); all-zero = none */
	__u16 gw_port;      /* gateway port, host order; 0 = any */
	__u8  allow_dns;    /* 1 = allow :53 egress */
	__u8  enforce;      /* 1 = block (-EPERM), 0 = observe-only */
	__u8  dns_v4[3][4]; /* resolver IPv4s (network order); :53 allowed only to these.
	                     * all-zero (no resolvers set) = legacy allow-any :53 (fail-functional). */
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct oknek_egress_policy);
	/* RDONLY_PROG: same hardening as oknek_self_id. Map.Freeze() (SetEgressPolicy)
	 * blocks only the userspace bpf() syscall write; a root-loaded FOREIGN program
	 * could otherwise write this frozen policy and flip enforce=0, disabling the R11
	 * jail (verified bypass). This flag makes the verifier reject program writes.
	 * Only the loader's userspace Put (before Freeze) writes it; the hooks only read. */
	__uint(map_flags, BPF_F_RDONLY_PROG);
} oknek_egress SEC(".maps");

/* Fork-propagated watch set: every descendant of a watched agent is added here
 * at fork time (raw_tp/sched_process_fork), so watched-ness survives re-parenting
 * (the double-fork-to-init escape) and the bounded ancestry walk. Keyed by tgid;
 * cleaned on process exit. Value = the inherited agent_id. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, char[AGENT_LEN]);
} oknek_watched_tasks SEC(".maps");

/* Protected files matched by INODE (dev, ino) — immune to the hardlink / rename /
 * bind-mount tricks that defeat the name match. Populated by the daemon from the
 * configured protected_files (resolved to dev+ino at startup). */
struct oknek_inode_key { __u64 ino; __u32 dev; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct oknek_inode_key);
	__type(value, __u8);
} oknek_protected_inodes SEC(".maps");

/* R22 supply-chain pins + R23 canaries. A watched agent may not WRITE a pinned
 * artifact (skill, hook, settings, MCP manifest) in place; an artifact the daemon's
 * integrity sweep found TAMPERED is quarantined — no open, no exec, by a watched
 * agent — until a human re-pins it. Canaries are planted decoy credentials: any
 * watched open is a high-confidence alarm (val 1 = alert) or a block (val 2).
 * All keyed by (dev, ino) like oknek_protected_inodes: hardlink/rename-proof. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct oknek_inode_key);
	__type(value, __u8);
} oknek_pinned_inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct oknek_inode_key);
	__type(value, __u8);
} oknek_quarantine_inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct oknek_inode_key);
	__type(value, __u8); /* 1 alert, 2 block */
} oknek_canary_inodes SEC(".maps");

/* R21 Rule of Two (Meta, 2025-10-31): in one session an agent may hold at most two
 * of {U untrusted input, P private data, X external comms}. Taint is keyed by AGENT
 * IDENTITY (not pid) so a child `cat`'s untrusted read taints the whole session.
 * Mode is per Okredo policy: 0 off, 1 observe (log the would-deny), 2 enforce. The
 * hook that would grant the THIRD property returns -EPERM. Untrusted/private sets
 * are (dev,ino) maps for files and for parent directories (direct children). */
struct oknek_agent_key { char id[AGENT_LEN]; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct oknek_agent_key);
	__type(value, __u8); /* bits: U=1 P=2 X=4 */
} oknek_taint SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);  /* Okredo policy id */
	__type(value, __u8); /* 0 off, 1 observe, 2 enforce */
} oknek_r2_mode SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024); __type(key, struct oknek_inode_key); __type(value, __u8); } oknek_untrusted_inodes SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);  __type(key, struct oknek_inode_key); __type(value, __u8); } oknek_untrusted_dirs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024); __type(key, struct oknek_inode_key); __type(value, __u8); } oknek_private_inodes SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);  __type(key, struct oknek_inode_key); __type(value, __u8); } oknek_private_dirs SEC(".maps");

/* Okredo (IAM): per-agent identity -> authorization. oknek_agent_policy maps a
 * watched agent's tgid to its profile/policy id (set by the daemon at registration
 * from `oknek run --profile`). oknek_egress_allow is the per-policy egress allowlist
 * keyed by {policy, port, ip}: a destination THIS agent's identity is cleared to
 * reach, additive to the base egress jail. Different identity -> different verdict. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   /* tgid */
	__type(value, __u16); /* policy id (0 = none/base) */
} oknek_agent_policy SEC(".maps");

struct oknek_allow_key { __u16 policy; __u16 port; __u8 ip[4]; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct oknek_allow_key);
	__type(value, __u8);
} oknek_egress_allow SEC(".maps");

/* Okredo CIDR grants: an identity may be cleared to reach a whole byte-aligned
 * range (e.g. 140.82.0.0/16:443). Small array, scanned in a bounded loop. */
#define OKREDO_CIDR_MAX 32
struct oknek_cidr { __u16 policy; __u16 port; __u8 net[4]; __u8 nbytes; __u8 _pad[3]; };
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OKREDO_CIDR_MAX);
	__type(key, __u32);
	__type(value, struct oknek_cidr);
} oknek_egress_cidr SEC(".maps");

/* R20 anti-unpin (self-pin-guard): the bpffs pin dir's own identity. The loader
 * writes the pin dir's (dev, ino) here AFTER creating it; the inode_unlink/rename
 * hooks deny any op that targets THIS inode — so root cannot `rm` or `mv` away the
 * very pins that keep enforcement alive. Keyed on dev+ino (never bare ino: i_ino is
 * unique only within a filesystem and WILL collide across mounts). enforce: 1=block,
 * 0=observe. dev==0 && ino==0 = uninitialised => fail-OPEN (the tiny boot window
 * before the loader writes it; Part C's heartbeat covers that gap). Unlike every
 * other oknek rule this is NOT scoped to watched agents — it guards oknek's own
 * off-switch against anyone, including a root insider. */
struct oknek_selfid { __u64 ino; __u32 dev; __u32 enforce; };
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct oknek_selfid);
	/* RDONLY_PROG: read-only to ALL BPF programs. Map.Freeze() only blocks the
	 * userspace bpf() syscall write path — a root-loaded FOREIGN program can still
	 * write a merely-frozen map and flip enforce=0 (verified bypass). This flag makes
	 * the verifier REJECT any program write to this map at load. Userspace can still
	 * write it BEFORE freeze (the loader's one-shot Put in ArmSelfGuard), so arming is
	 * unaffected; oknek's own selfguard only READS it. RDONLY_PROG (programs) + Freeze
	 * (userspace) together = fully immutable once armed. */
	__uint(map_flags, BPF_F_RDONLY_PROG);
} oknek_self_id SEC(".maps");

/* loader-tunable: 1 = block (-EPERM), 0 = observe only. */
const volatile __u8 oknek_enforce = 1;

/* exact compare through the NUL; n includes the terminator. */
static __always_inline int streq(const char *a, const char *b, int n) {
	for (int i = 0; i < n; i++) {
		char ca = a[i];
		if (ca != b[i]) return 0;
		if (ca == '\0') return 1;
	}
	return 1;
}

/* watched = directly registered (oknek_agent_pids) OR a fork-propagated
 * descendant (oknek_watched_tasks). The latter survives re-parenting + exec. */
static __always_inline char *oknek_is_watched(__u32 tgid) {
	char *a = bpf_map_lookup_elem(&oknek_agent_pids, &tgid);
	if (a) return a;
	return bpf_map_lookup_elem(&oknek_watched_tasks, &tgid);
}

/* R21: the Rule-of-Two mode for the current process's Okredo identity (0 = off). */
static __always_inline __u8 oknek_r2_mode_of(__u32 tgid) {
	__u16 *polp = bpf_map_lookup_elem(&oknek_agent_policy, &tgid);
	if (!polp || !*polp) return 0;
	__u16 pol = *polp;
	__u8 *m = bpf_map_lookup_elem(&oknek_r2_mode, &pol);
	return m ? *m : 0;
}

/* R21: merge `bits` into the agent's session taint. Returns 1 when this op would be
 * the THIRD property and mode is enforce (caller returns -EPERM). Emits an R21 event
 * on every newly-acquired bit (verdict 1, _pad 0) and on a third-bit attempt
 * (_pad 1; verdict 2 = denied, 1 = would-deny in observe). */
static __always_inline int oknek_r2_touch(__u32 pid, char *agent, __u8 bits, __u8 mode,
                                          char *dir, char *name, __u8 *daddr, __u16 dport, __u8 family) {
	struct oknek_agent_key k = {};
	__builtin_memcpy(k.id, agent, AGENT_LEN);
	__u8 cur = 0;
	__u8 *tp = bpf_map_lookup_elem(&oknek_taint, &k);
	if (tp) cur = *tp;
	__u8 next = cur | bits;
	if (next == cur) return 0;
	int three = (next & 1) && (next & 2) && (next & 4);
	if (!three) bpf_map_update_elem(&oknek_taint, &k, &next, BPF_ANY);
	int deny = (three && mode == 2 && oknek_enforce) ? 1 : 0;
	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->rule = 21; e->verdict = deny ? 2 : 1; e->category = next; e->_pad = three ? 1 : 0;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		if (dir) __builtin_memcpy(e->dir, dir, NAME_LEN);
		if (name) __builtin_memcpy(e->name, name, NAME_LEN);
		if (daddr) __builtin_memcpy(e->daddr, daddr, 16);
		e->dport = dport; e->family = family;
		bpf_ringbuf_submit(e, 0);
	}
	return deny;
}

/* Emit a file-shaped event (rule/verdict/category + dir/name) for R22/R23. */
static __always_inline void oknek_emit_file(__u32 pid, char *agent, __u8 rule, __u8 verdict, __u8 cat, char *dir, char *name) {
	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (!e) return;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->rule = rule; e->verdict = verdict; e->category = cat;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
	__builtin_memcpy(e->dir, dir, NAME_LEN);
	__builtin_memcpy(e->name, name, NAME_LEN);
	bpf_ringbuf_submit(e, 0);
}

SEC("lsm/file_open")
int BPF_PROG(oknek_file_open, struct file *file, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(pid);
	if (!agent) return 0; /* only enforce watched agents (now incl. fork-propagated) */

	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry) return 0;

	char name[NAME_LEN] = {};
	char dir[NAME_LEN] = {};
	const unsigned char *np = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(name, sizeof(name), np);
	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
	const unsigned char *dp = BPF_CORE_READ(parent, d_name.name);
	bpf_probe_read_kernel_str(dir, sizeof(dir), dp);

	/* R23 canary / R22 pin+quarantine — inode-keyed, checked BEFORE the R3 name
	 * patterns so a planted ~/.aws/credentials reports as a canary, not R3. */
	{
		struct oknek_inode_key ik = {};
		struct inode *fi = BPF_CORE_READ(file, f_inode);
		if (fi) {
			ik.ino = BPF_CORE_READ(fi, i_ino);
			ik.dev = BPF_CORE_READ(fi, i_sb, s_dev);
			__u8 *cv = bpf_map_lookup_elem(&oknek_canary_inodes, &ik);
			if (cv) {
				__u8 mode = *cv;
				oknek_emit_file(pid, agent, 23, mode == 2 ? 2 : 1, mode, dir, name);
				if (mode == 2 && oknek_enforce) return -EPERM;
				/* R21: a canary read is a private-data touch (P) for the session. */
				{
					__u8 r2m = oknek_r2_mode_of(pid);
					if (r2m && oknek_r2_touch(pid, agent, 2, r2m, dir, name, 0, 0, 0)) return -EPERM;
				}
				return 0; /* alert mode: let it through — the alarm is the point */
			}
			if (bpf_map_lookup_elem(&oknek_quarantine_inodes, &ik)) {
				oknek_emit_file(pid, agent, 22, 2, 2, dir, name);
				if (oknek_enforce) return -EPERM;
				return 0;
			}
			__u32 fm = BPF_CORE_READ(file, f_mode);
			if ((fm & 0x2) && bpf_map_lookup_elem(&oknek_pinned_inodes, &ik)) {
				oknek_emit_file(pid, agent, 22, 2, 1, dir, name);
				if (oknek_enforce) return -EPERM;
				return 0;
			}
		}
	}

	/* R21 Rule of Two — READ of untrusted input (U) or private data (P). */
	{
		__u8 r2m = oknek_r2_mode_of(pid);
		if (r2m) {
			__u32 fmr = BPF_CORE_READ(file, f_mode);
			if (fmr & 0x1) {
				struct oknek_inode_key ik2 = {}, pk = {};
				struct inode *fi2 = BPF_CORE_READ(file, f_inode);
				if (fi2) {
					ik2.ino = BPF_CORE_READ(fi2, i_ino);
					ik2.dev = BPF_CORE_READ(fi2, i_sb, s_dev);
				}
				if (parent) {
					struct inode *pi = BPF_CORE_READ(parent, d_inode);
					if (pi) {
						pk.ino = BPF_CORE_READ(pi, i_ino);
						pk.dev = BPF_CORE_READ(pi, i_sb, s_dev);
					}
				}
				__u8 bits = 0;
				if (bpf_map_lookup_elem(&oknek_untrusted_inodes, &ik2) || bpf_map_lookup_elem(&oknek_untrusted_dirs, &pk)) bits |= 1;
				if (bpf_map_lookup_elem(&oknek_private_inodes, &ik2) || bpf_map_lookup_elem(&oknek_private_dirs, &pk)) bits |= 2;
				if (bits && oknek_r2_touch(pid, agent, bits, r2m, dir, name, 0, 0, 0)) return -EPERM;
			}
		}
	}

	/* R14 — persistence/backdoor WRITE guard. A watched agent WRITING to a survival/
	 * escalation location (cron, authorized_keys, ld.so.preload, sudoers, passwd, shell
	 * rc) is the persist leg of the attack. Reads are fine (creds are R3's job) — the
	 * WRITE is the attack. f_mode carries FMODE_WRITE (0x2). */
	__u32 fmode = BPF_CORE_READ(file, f_mode);
	if (fmode & 0x2) {
		int phit = 0;
		if (streq(dir, "etc", 4) && (streq(name, "crontab", 8) || streq(name, "ld.so.preload", 14) ||
		    streq(name, "sudoers", 8) || streq(name, "passwd", 7))) phit = 1;
		else if (streq(dir, "cron.d", 7) || streq(dir, "sudoers.d", 10)) phit = 1;
		else if (streq(dir, ".ssh", 5) && streq(name, "authorized_keys", 16)) phit = 1;
		else if (streq(name, ".bashrc", 8) || streq(name, ".zshrc", 7) ||
		         streq(name, ".bash_profile", 14) || streq(name, ".profile", 9)) phit = 1;
		if (phit) {
			struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
			if (e) {
				__builtin_memset(e, 0, sizeof(*e));
				e->ts_ns = bpf_ktime_get_ns();
				e->pid = pid;
				e->rule = 14; e->verdict = 2;
				bpf_get_current_comm(&e->comm, sizeof(e->comm));
				__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
				__builtin_memcpy(e->dir, dir, NAME_LEN);
				__builtin_memcpy(e->name, name, NAME_LEN);
				bpf_ringbuf_submit(e, 0);
			}
			if (oknek_enforce) return -EPERM;
			return 0;
		}
	}

	int hit = 0; __u8 cat = 3;
	if (streq(name, ".claude.json", 13) || streq(name, ".claudeconfig.json", 19) ||
	    streq(name, ".netrc", 7) || streq(name, ".pgpass", 8) || streq(name, ".npmrc", 7)) { hit = 1; cat = 3; }
	else if (streq(name, ".env", 5) || streq(name, ".env.local", 11) || streq(name, ".env.production", 16) ||
	         streq(name, ".env.development", 17) || streq(name, ".env.staging", 13)) { hit = 1; cat = 3; }
	else if (streq(dir, ".aws", 5) && (streq(name, "credentials", 12) || streq(name, "config", 7))) { hit = 1; cat = 1; }
	else if (streq(dir, ".ssh", 5) && (streq(name, "id_rsa", 7) || streq(name, "id_ed25519", 11) ||
	         streq(name, "id_ecdsa", 9) || streq(name, "id_dsa", 7) || streq(name, "identity", 9))) { hit = 1; cat = 2; }
	else if (streq(dir, ".gnupg", 7) || streq(dir, ".gemini", 8) || streq(dir, ".codex", 7)) { hit = 1; cat = 2; }
	else if (streq(dir, ".kube", 6) && streq(name, "config", 7)) { hit = 1; cat = 2; }
	else if (streq(dir, ".docker", 8) && streq(name, "config.json", 12)) { hit = 1; cat = 2; }
	else if (streq(dir, ".claude", 8) && streq(name, "credentials", 12)) { hit = 1; cat = 2; }
	else if (streq(dir, "etc", 4) && streq(name, "shadow", 7)) { hit = 1; cat = 0; }

	/* inode match — catches the same file opened via a hardlink / renamed / bind-mounted
	 * path (different name, same dev+ino). Immune to the name-pattern evasions. */
	if (!hit) {
		struct inode *finode = BPF_CORE_READ(file, f_inode);
		if (finode) {
			struct oknek_inode_key ik = {};
			ik.ino = BPF_CORE_READ(finode, i_ino);
			ik.dev = BPF_CORE_READ(finode, i_sb, s_dev);
			if (bpf_map_lookup_elem(&oknek_protected_inodes, &ik)) { hit = 1; cat = 0; }
		}
	}

	if (!hit) return 0;

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->ppid = 0;
		e->rule = 3; e->verdict = 2; e->category = cat; e->_pad = 0;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		__builtin_memcpy(e->dir, dir, NAME_LEN);
		__builtin_memcpy(e->name, name, NAME_LEN);
		bpf_ringbuf_submit(e, 0);
	}

	if (oknek_enforce) return -EPERM;
	return 0;
}

/* Walk up the process tree (bounded); return the watched agent_id ptr, or NULL.
 * This is what makes a spawned static binary inescapable: even a child that never
 * loaded the libc shim is caught because an ancestor PID is in oknek_agent_pids. */
static __always_inline char *oknek_watched_ancestry(void) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
#pragma unroll
	for (int i = 0; i < ANCESTRY_MAX; i++) {
		if (!task) break;
		__u32 tgid = BPF_CORE_READ(task, tgid);
		char *agent = bpf_map_lookup_elem(&oknek_agent_pids, &tgid);
		if (agent) return agent;
		struct task_struct *parent = BPF_CORE_READ(task, real_parent);
		if (!parent || parent == task) break;
		task = parent;
	}
	return NULL;
}

/* R11 egress jail: a watched agent's whole process tree may only reach the
 * configured gateway (+ DNS + loopback); every other outbound connect is
 * blocked in the kernel, so route-around to an LLM provider is impossible. */
SEC("lsm/socket_connect")
int BPF_PROG(oknek_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */

	__u16 family = BPF_CORE_READ(address, sa_family);
	if (family != AF_INET && family != AF_INET6) return 0; /* never gate unix etc. */

	__u32 cur = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(cur);        /* fork-propagated: catches reparented children */
	if (!agent) agent = oknek_watched_ancestry(); /* fallback: live ancestry walk */
	if (!agent) return 0; /* not a watched process tree */

	__u32 zero = 0;
	struct oknek_egress_policy *pol = bpf_map_lookup_elem(&oknek_egress, &zero);
	if (!pol) return 0; /* fail-safe: no policy => allow */

	__u8 daddr[16] = {};
	__u16 dport = 0;
	int allow = 0;
	int external = 0; /* R21: allowed by an identity grant (non-gateway) */

	if (family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)address;
		__u32 ip = BPF_CORE_READ(in, sin_addr.s_addr); /* network order */
		__builtin_memcpy(daddr, &ip, 4);
		dport = bpf_ntohs(BPF_CORE_READ(in, sin_port));
		if (daddr[0] == 127) {
			/* loopback restricted to the gateway port + local DNS (:53): shuts the
			 * loopback->unwatched-proxy pivot so a watched agent can't tunnel out
			 * through an arbitrary local forwarder. gw_port==0 (any) keeps legacy allow-all. */
			if (pol->gw_port == 0 || dport == pol->gw_port) allow = 1;
			else if (pol->allow_dns && dport == 53) allow = 1;
		} else {
			int gw_set = pol->gw_v4[0] | pol->gw_v4[1] | pol->gw_v4[2] | pol->gw_v4[3];
			int eq = daddr[0] == pol->gw_v4[0] && daddr[1] == pol->gw_v4[1] &&
			         daddr[2] == pol->gw_v4[2] && daddr[3] == pol->gw_v4[3];
			if (gw_set && eq && (pol->gw_port == 0 || dport == pol->gw_port)) allow = 1;
			else if (pol->allow_dns && dport == 53) {
				/* :53 only to a configured resolver; if none set, legacy allow-any. */
				int any_resolver = 0;
#pragma unroll
				for (int i = 0; i < 3; i++) {
					int nz = pol->dns_v4[i][0] | pol->dns_v4[i][1] | pol->dns_v4[i][2] | pol->dns_v4[i][3];
					if (nz) {
						any_resolver = 1;
						if (daddr[0] == pol->dns_v4[i][0] && daddr[1] == pol->dns_v4[i][1] &&
						    daddr[2] == pol->dns_v4[i][2] && daddr[3] == pol->dns_v4[i][3]) allow = 1;
					}
				}
				if (!any_resolver) allow = 1;
			}
		}
	} else { /* AF_INET6 — v1 allows only ::1 loopback */
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)address;
		BPF_CORE_READ_INTO(&daddr, in6, sin6_addr);
		dport = bpf_ntohs(BPF_CORE_READ(in6, sin6_port));
		int nonzero = 0;
		for (int i = 0; i < 15; i++) nonzero |= daddr[i];
		if (!nonzero && daddr[15] == 1) { /* ::1 loopback — same port restriction */
			if (pol->gw_port == 0 || dport == pol->gw_port) allow = 1;
			else if (pol->allow_dns && dport == 53) allow = 1;
		}
	}

	/* Okredo: if the base jail didn't allow it, check this agent's identity-scoped
	 * egress allowlist — a destination its profile is authorized to reach. Same dest,
	 * different agent identity -> different verdict. (v4 allowlist; v6 = v2.) */
	if (!allow && family == AF_INET) {
		__u16 *polp = bpf_map_lookup_elem(&oknek_agent_policy, &cur);
		if (polp && *polp) {
			__u16 pol_id = *polp;
			struct oknek_allow_key ak = {};
			ak.policy = pol_id;
			ak.port = dport;
			ak.ip[0] = daddr[0]; ak.ip[1] = daddr[1]; ak.ip[2] = daddr[2]; ak.ip[3] = daddr[3];
			if (bpf_map_lookup_elem(&oknek_egress_allow, &ak)) { allow = 1; external = 1; }
			/* CIDR grants: scan the small array for a byte-aligned range match. */
#pragma unroll
			for (int i = 0; i < OKREDO_CIDR_MAX && !allow; i++) {
				__u32 idx = i;
				struct oknek_cidr *cd = bpf_map_lookup_elem(&oknek_egress_cidr, &idx);
				if (!cd || cd->nbytes == 0 || cd->policy != pol_id) continue;
				if (cd->port != 0 && cd->port != dport) continue;
				int m = 1;
				for (int b = 0; b < 4; b++)
					if (b < cd->nbytes && cd->net[b] != daddr[b]) m = 0;
				if (m) { allow = 1; external = 1; }
			}
		}
	}

	if (allow) {
		/* R21: an identity-granted external destination = untrusted input + external comms. */
		if (external) {
			__u32 r2pid = bpf_get_current_pid_tgid() >> 32;
			__u8 r2m = oknek_r2_mode_of(r2pid);
			__u16 nk = 0xFFFF; /* r2_mode[0xFFFF] = 1 -> network is TRUSTED (connect = X only) */
			__u8 *nt = bpf_map_lookup_elem(&oknek_r2_mode, &nk);
			__u8 nbits = (nt && *nt) ? 4 : (1 | 4);
			if (r2m && oknek_r2_touch(r2pid, agent, nbits, r2m, 0, 0, daddr, dport, (__u8)family)) return -EPERM;
		}
		return 0;
	}

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->rule = 11; e->verdict = pol->enforce ? 2 : 1; /* 2=block, 1=observe(allowed) */
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		__builtin_memcpy(e->daddr, daddr, 16);
		e->dport = dport;
		e->family = (__u8)family;
		bpf_ringbuf_submit(e, 0);
	}
	return pol->enforce ? -EPERM : 0;
}

/* Propagate watched-ness to children AT FORK — the fix for the double-fork /
 * re-parent-to-init escape. Any child of a watched task is itself watched, keyed
 * by its own tgid, so it stays watched no matter who its parent later becomes. */
SEC("raw_tp/sched_process_fork")
int BPF_PROG(oknek_fork, struct task_struct *parent, struct task_struct *child) {
	__u32 ptgid = BPF_CORE_READ(parent, tgid);
	char *agent = oknek_is_watched(ptgid);
	if (!agent) return 0;
	__u32 ctgid = BPF_CORE_READ(child, tgid);
	char val[AGENT_LEN];
	__builtin_memcpy(val, agent, AGENT_LEN);
	bpf_map_update_elem(&oknek_watched_tasks, &ctgid, val, BPF_ANY);
	/* Okredo: a child inherits its parent's authorization policy, so a real
	 * multi-process agent's spawned workers keep the same identity-scoped grants. */
	__u16 *cpol = bpf_map_lookup_elem(&oknek_agent_policy, &ptgid);
	if (cpol) {
		__u16 pv = *cpol;
		bpf_map_update_elem(&oknek_agent_policy, &ctgid, &pv, BPF_ANY);
	}
	return 0;
}

/* Clean the propagated set when a process (thread-group leader) exits, so the map
 * stays bounded and a reused pid is never falsely watched. */
SEC("raw_tp/sched_process_exit")
int BPF_PROG(oknek_exit, struct task_struct *task) {
	__u32 pid = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);
	if (pid == tgid) {
		bpf_map_delete_elem(&oknek_watched_tasks, &tgid);
		/* NOTE: do NOT delete oknek_agent_policy here. A Go agent execs from a
		 * worker thread, which makes the old thread-group leader exit (pid==tgid) —
		 * a spurious "exit" that would wipe a LIVE agent's policy. agent_policy has
		 * no ancestry fallback (unlike watched_tasks), so it must not be cleaned on
		 * this signal. Entries are bounded (max 4096) and reaped on pid reuse; proper
		 * daemon-driven lifecycle is a v3 follow-up. */
	}
	return 0;
}

/* R11 also gates CONNECTIONLESS egress — UDP sendto / QUIC / raw datagrams that
 * never call connect() and so never hit lsm/socket_connect. Same gateway/DNS/
 * loopback policy, applied at lsm/socket_sendmsg. msg_name is the kernel-side
 * destination sockaddr (NULL for a connected socket — already gated at connect). */
SEC("lsm/socket_sendmsg")
int BPF_PROG(oknek_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size, int ret) {
	if (ret != 0) return ret;
	void *name = BPF_CORE_READ(msg, msg_name);
	if (!name) return 0; /* connected socket: connect() already decided */

	char *agent = oknek_is_watched(bpf_get_current_pid_tgid() >> 32);
	if (!agent) agent = oknek_watched_ancestry();
	if (!agent) return 0;

	__u16 family = 0;
	bpf_probe_read_kernel(&family, sizeof(family), name);
	if (family != AF_INET && family != AF_INET6) return 0;

	__u32 zero = 0;
	struct oknek_egress_policy *pol = bpf_map_lookup_elem(&oknek_egress, &zero);
	if (!pol) return 0;

	__u8 daddr[16] = {};
	__u16 dport = 0;
	int allow = 0;
	int external = 0; /* R21: allowed by an identity grant (non-gateway) */
	if (family == AF_INET) {
		bpf_probe_read_kernel(daddr, 4, (__u8 *)name + 4); /* sin_addr @ offset 4 */
		__u16 pbe = 0;
		bpf_probe_read_kernel(&pbe, 2, (__u8 *)name + 2);  /* sin_port @ offset 2 */
		dport = bpf_ntohs(pbe);
		if (daddr[0] == 127) {
			/* loopback restricted to gateway port + local DNS (shuts proxy-pivot). */
			if (pol->gw_port == 0 || dport == pol->gw_port) allow = 1;
			else if (pol->allow_dns && dport == 53) allow = 1;
		} else {
			int gw_set = pol->gw_v4[0] | pol->gw_v4[1] | pol->gw_v4[2] | pol->gw_v4[3];
			int eq = daddr[0] == pol->gw_v4[0] && daddr[1] == pol->gw_v4[1] &&
			         daddr[2] == pol->gw_v4[2] && daddr[3] == pol->gw_v4[3];
			if (gw_set && eq && (pol->gw_port == 0 || dport == pol->gw_port)) allow = 1;
			else if (pol->allow_dns && dport == 53) {
				int any_resolver = 0;
#pragma unroll
				for (int i = 0; i < 3; i++) {
					int nz = pol->dns_v4[i][0] | pol->dns_v4[i][1] | pol->dns_v4[i][2] | pol->dns_v4[i][3];
					if (nz) {
						any_resolver = 1;
						if (daddr[0] == pol->dns_v4[i][0] && daddr[1] == pol->dns_v4[i][1] &&
						    daddr[2] == pol->dns_v4[i][2] && daddr[3] == pol->dns_v4[i][3]) allow = 1;
					}
				}
				if (!any_resolver) allow = 1;
			}
		}
	} else {
		bpf_probe_read_kernel(daddr, 16, (__u8 *)name + 8); /* sin6_addr @ offset 8 */
		__u16 pbe = 0;
		bpf_probe_read_kernel(&pbe, 2, (__u8 *)name + 2);   /* sin6_port @ offset 2 */
		dport = bpf_ntohs(pbe);
		int nonzero = 0;
		for (int i = 0; i < 15; i++) nonzero |= daddr[i];
		if (!nonzero && daddr[15] == 1) { /* ::1 loopback — same port restriction */
			if (pol->gw_port == 0 || dport == pol->gw_port) allow = 1;
			else if (pol->allow_dns && dport == 53) allow = 1;
		}
	}

	/* Okredo: per-agent identity-scoped allowlist for connectionless (UDP/QUIC) sends. */
	if (!allow && family == AF_INET) {
		__u32 mcur = bpf_get_current_pid_tgid() >> 32;
		__u16 *polp = bpf_map_lookup_elem(&oknek_agent_policy, &mcur);
		if (polp && *polp) {
			__u16 pol_id = *polp;
			struct oknek_allow_key ak = {};
			ak.policy = pol_id;
			ak.port = dport;
			ak.ip[0] = daddr[0]; ak.ip[1] = daddr[1]; ak.ip[2] = daddr[2]; ak.ip[3] = daddr[3];
			if (bpf_map_lookup_elem(&oknek_egress_allow, &ak)) { allow = 1; external = 1; }
#pragma unroll
			for (int i = 0; i < OKREDO_CIDR_MAX && !allow; i++) {
				__u32 idx = i;
				struct oknek_cidr *cd = bpf_map_lookup_elem(&oknek_egress_cidr, &idx);
				if (!cd || cd->nbytes == 0 || cd->policy != pol_id) continue;
				if (cd->port != 0 && cd->port != dport) continue;
				int m = 1;
				for (int b = 0; b < 4; b++)
					if (b < cd->nbytes && cd->net[b] != daddr[b]) m = 0;
				if (m) { allow = 1; external = 1; }
			}
		}
	}

	if (allow) {
		/* R21: an identity-granted external destination = untrusted input + external comms. */
		if (external) {
			__u32 r2pid = bpf_get_current_pid_tgid() >> 32;
			__u8 r2m = oknek_r2_mode_of(r2pid);
			__u16 nk = 0xFFFF; /* r2_mode[0xFFFF] = 1 -> network is TRUSTED (connect = X only) */
			__u8 *nt = bpf_map_lookup_elem(&oknek_r2_mode, &nk);
			__u8 nbits = (nt && *nt) ? 4 : (1 | 4);
			if (r2m && oknek_r2_touch(r2pid, agent, nbits, r2m, 0, 0, daddr, dport, (__u8)family)) return -EPERM;
		}
		return 0;
	}

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->rule = 11; e->verdict = pol->enforce ? 2 : 1; /* 2=block, 1=observe(allowed) */
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		__builtin_memcpy(e->daddr, daddr, 16);
		e->dport = dport;
		e->family = (__u8)family;
		bpf_ringbuf_submit(e, 0);
	}
	return pol->enforce ? -EPERM : 0;
}

/* R13 — close the MEMORY credential lane. A rogue agent that can't read a cred
 * FILE (R3 name+inode) can still try to lift it out of another process's memory:
 * process_vm_readv, /proc/<pid>/mem, /proc/<pid>/environ. All three funnel through
 * ptrace_may_access -> this LSM hook. The kernel returns early for same-thread-group
 * (self) access BEFORE the hook fires, so a watched agent still reads its OWN memory;
 * only CROSS-process reads reach here. Block them: a credential can't be read out of
 * a neighbouring process. Cred protection is always-on (oknek_enforce), like R3. */
SEC("lsm/ptrace_access_check")
int BPF_PROG(oknek_ptrace, struct task_struct *child, unsigned int mode, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(pid);
	if (!agent) agent = oknek_watched_ancestry();
	if (!agent) return 0; /* only watched agents (incl. fork-propagated) */

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->ppid = BPF_CORE_READ(child, tgid); /* the target process being read */
		e->rule = 13; e->verdict = 2;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		bpf_ringbuf_submit(e, 0);
	}
	if (oknek_enforce) return -EPERM;
	return 0;
}

/* R15 — privilege-escalation guard (the "escalate" leg). A watched agent should
 * never need to become root; exec of a setuid escalation helper (sudo/su/pkexec/
 * doas/...) is the escalation move. Block it at exec. bprm->file is the binary
 * being exec'd; we match its basename. Scoped to watched agents (incl. fork-prop). */
SEC("lsm/bprm_check_security")
int BPF_PROG(oknek_exec, struct linux_binprm *bprm, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(pid);
	if (!agent) agent = oknek_watched_ancestry();
	if (!agent) return 0;

	struct dentry *de = BPF_CORE_READ(bprm, file, f_path.dentry);
	char name[NAME_LEN] = {};
	const unsigned char *np = BPF_CORE_READ(de, d_name.name);
	bpf_probe_read_kernel_str(name, sizeof(name), np);

	/* R22 — exec of a QUARANTINED (tampered) artifact by a watched agent. Interpreted
	 * scripts are caught at file_open by the interpreter's read; this catches a
	 * tampered ELF/binary skill executed directly. */
	{
		struct oknek_inode_key xk = {};
		struct inode *xi = BPF_CORE_READ(bprm, file, f_inode);
		if (xi) {
			xk.ino = BPF_CORE_READ(xi, i_ino);
			xk.dev = BPF_CORE_READ(xi, i_sb, s_dev);
			if (bpf_map_lookup_elem(&oknek_quarantine_inodes, &xk)) {
				char nodir[NAME_LEN] = {};
				oknek_emit_file(pid, agent, 22, 2, 3, nodir, name);
				if (oknek_enforce) return -EPERM;
				return 0;
			}
		}
	}

	int phit = 0;
	if (streq(name, "sudo", 5) || streq(name, "su", 3) || streq(name, "pkexec", 7) ||
	    streq(name, "doas", 5) || streq(name, "sudoedit", 9) || streq(name, "newgrp", 7)) phit = 1;
	if (!phit) {
		/* exec-observed (rule 30, verdict 0 = informational): lets the daemon bind a
		 * spawned MCP server to its own identity (R24) by reading /proc/<pid>/cmdline.
		 * ppid = the real parent's tgid. Never denies. */
		struct oknek_event *x = bpf_ringbuf_reserve(&oknek_events, sizeof(*x), 0);
		if (x) {
			__builtin_memset(x, 0, sizeof(*x));
			x->ts_ns = bpf_ktime_get_ns();
			x->pid = pid;
			struct task_struct *t = (struct task_struct *)bpf_get_current_task();
			struct task_struct *rp = BPF_CORE_READ(t, real_parent);
			if (rp) x->ppid = BPF_CORE_READ(rp, tgid);
			x->rule = 30; x->verdict = 0;
			bpf_get_current_comm(&x->comm, sizeof(x->comm));
			__builtin_memcpy(x->agent_id, agent, AGENT_LEN);
			__builtin_memcpy(x->name, name, NAME_LEN);
			bpf_ringbuf_submit(x, 0);
		}
		return 0;
	}

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->rule = 15; e->verdict = 2;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		__builtin_memcpy(e->name, name, NAME_LEN);
		bpf_ringbuf_submit(e, 0);
	}
	if (oknek_enforce) return -EPERM;
	return 0;
}

/* R16 — inbound-backdoor guard (the "listen" leg). R11 stops a watched agent
 * reaching OUT; R16 stops it accepting IN. Binding an externally-reachable
 * listener (0.0.0.0 or a real interface IP) is a bind-shell/backdoor. Block it at
 * socket_bind; loopback binds (127/8, ::1) are allowed so local-only services work. */
SEC("lsm/socket_bind")
int BPF_PROG(oknek_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	__u16 family = 0;
	bpf_probe_read_kernel(&family, sizeof(family), address);
	if (family != AF_INET && family != AF_INET6) return 0; /* never gate unix etc. */

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(pid);
	if (!agent) agent = oknek_watched_ancestry();
	if (!agent) return 0;

	__u8 baddr[16] = {};
	__u16 bport = 0;
	int allow = 0;
	if (family == AF_INET) {
		bpf_probe_read_kernel(baddr, 4, (__u8 *)address + 4);  /* sin_addr @ 4 */
		__u16 pbe = 0;
		bpf_probe_read_kernel(&pbe, 2, (__u8 *)address + 2);   /* sin_port @ 2 */
		bport = bpf_ntohs(pbe);
		if (baddr[0] == 127) allow = 1;                        /* loopback bind OK */
	} else {
		bpf_probe_read_kernel(baddr, 16, (__u8 *)address + 8); /* sin6_addr @ 8 */
		__u16 pbe = 0;
		bpf_probe_read_kernel(&pbe, 2, (__u8 *)address + 2);
		bport = bpf_ntohs(pbe);
		int nz = 0;
		for (int i = 0; i < 15; i++) nz |= baddr[i];
		if (!nz && baddr[15] == 1) allow = 1;                  /* ::1 */
	}
	if (allow) return 0;

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->rule = 16; e->verdict = 2;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		__builtin_memcpy(e->daddr, baddr, 16);
		e->dport = bport;
		e->family = (__u8)family;
		bpf_ringbuf_submit(e, 0);
	}
	if (oknek_enforce) return -EPERM;
	return 0;
}

/* R17 — kernel-tamper / anti-rootkit guard (self-defense). A watched agent has no
 * business calling bpf(): it could load a BPF rootkit, or try to enumerate/detach
 * oknek's own programs. Block the whole syscall for watched agents. Pairs with the
 * pinned+frozen links (Class 3) so oknek can't be disabled from inside the host —
 * SIGKILL doesn't (pins survive) and bpf() can't (this hook). oknekd itself is not
 * a watched agent, so its own bpf() calls are unaffected. */
SEC("lsm/bpf")
int BPF_PROG(oknek_bpf, int cmd, union bpf_attr *attr, unsigned int size, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(pid);
	if (!agent) agent = oknek_watched_ancestry();
	if (!agent) return 0;

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->rule = 17; e->verdict = 2;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		bpf_ringbuf_submit(e, 0);
	}
	if (oknek_enforce) return -EPERM;
	return 0;
}

/* R18 — kernel-module-load guard (anti-rootkit). A watched agent loading a kernel
 * module (finit_module via insmod/modprobe) = a kernel rootkit: hide processes,
 * disable LSMs, own the box. The module image is read through kernel_read_file
 * with id READING_MODULE; block it for watched agents. Pairs with R17 (bpf()) as
 * the other in-kernel-code-injection path. */
SEC("lsm/kernel_read_file")
int BPF_PROG(oknek_kmod, struct file *file, enum kernel_read_file_id id, bool contents, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	if (id != READING_MODULE) return 0; /* only gate kernel-module image reads */
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(pid);
	if (!agent) agent = oknek_watched_ancestry();
	if (!agent) return 0;

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->rule = 18; e->verdict = 2;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		bpf_ringbuf_submit(e, 0);
	}
	if (oknek_enforce) return -EPERM;
	return 0;
}

/* R20 self-pin-guard core: deny an op whose target directory inode IS the bpffs
 * pin dir. Matches on (dev, ino) so it fires ONLY for oknek's own pin dir and
 * nothing else — ordinary unlink/rename anywhere else on the host is untouched
 * (the negative-scope guarantee that keeps this from bricking the box). Emits a
 * R20 DISABLE-attempt event regardless of enforce, then blocks iff enforce. */
static __always_inline int oknek_selfguard(struct inode *dir) {
	if (!dir) return 0;
	__u32 zero = 0;
	struct oknek_selfid *sid = bpf_map_lookup_elem(&oknek_self_id, &zero);
	if (!sid) return 0;                          /* fail-open: no map */
	if (sid->ino == 0 && sid->dev == 0) return 0; /* fail-open: not yet initialised */
	__u64 ino = BPF_CORE_READ(dir, i_ino);
	__u32 dev = BPF_CORE_READ(dir, i_sb, s_dev);
	if (ino != sid->ino || dev != sid->dev) return 0; /* not our pin dir -> allow */

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->rule = 20; e->verdict = sid->enforce ? 2 : 1; /* 2=block, 1=observe(allowed) */
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	return sid->enforce ? -EPERM : 0;
}

/* R20c — deny `umount` of the bpffs that holds oknek's pins. `umount /sys/fs/bpf`
 * (incl. lazy `umount -l`) drops every pin at once -> all links release -> the whole
 * `.o` detaches, with no rm/rename (so R20a/b never fire). Match the unmounted mount's
 * superblock dev against self_id.dev (the bpffs sb our pin dir lives on): fires ONLY for
 * our bpffs, not arbitrary umounts. Not scoped to watched agents (guards the pins vs
 * anyone, incl. root). Fail-open until armed; enforce-gated. */
SEC("lsm/sb_umount")
int BPF_PROG(oknek_sb_umount, struct vfsmount *mnt, int flags, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	if (!mnt) return 0;
	__u32 zero = 0;
	struct oknek_selfid *sid = bpf_map_lookup_elem(&oknek_self_id, &zero);
	if (!sid) return 0;                          /* fail-open: no map */
	if (sid->ino == 0 && sid->dev == 0) return 0; /* fail-open: not yet armed */
	__u32 dev = BPF_CORE_READ(mnt, mnt_sb, s_dev);
	if (dev != sid->dev) return 0;               /* not our pins' bpffs -> allow */

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->rule = 20; e->verdict = sid->enforce ? 2 : 1; e->category = 1; /* cat 1 = umount; 2=block,1=observe */
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	return sid->enforce ? -EPERM : 0;
}

/* R20a — deny `rm` of a pin. `dir` is the parent dir inode of the file being
 * unlinked; when it equals the pin dir, the file being removed is one of oknek's
 * own links. (rmdir of the dir is covered transitively: unlink is denied, so the
 * dir stays non-empty and rmdir fails on its own.) */
SEC("lsm/inode_unlink")
int BPF_PROG(oknek_inode_unlink, struct inode *dir, struct dentry *dentry, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	return oknek_selfguard(dir);
}

/* R20b — deny `mv` into/out of the pin dir (hide-by-move). Denied if EITHER the
 * source or destination directory is the pin dir. */
SEC("lsm/inode_rename")
int BPF_PROG(oknek_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret) {
	/* NB: the LSM inode_rename hook takes 4 args (no `flags` — that's on the VFS
	 * inode_operations->rename, not the security hook). Adding flags pushes the BPF
	 * ret slot past the kernel BTF func's arg count -> verifier rejects the load. */
	if (ret != 0) return ret; /* respect a prior LSM deny */
	int r = oknek_selfguard(old_dir);
	if (r) return r;
	return oknek_selfguard(new_dir);
}

/* R19 — mount guard (anti-escape). A watched agent mounting / remounting can escape
 * its view or hide paths: bind-mount over a watched directory, remount rw, mount a
 * fresh procfs to read other namespaces. Block sb_mount for watched agents. */
SEC("lsm/sb_mount")
int BPF_PROG(oknek_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data, int ret) {
	if (ret != 0) return ret; /* respect a prior LSM deny */
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	char *agent = oknek_is_watched(pid);
	if (!agent) agent = oknek_watched_ancestry();
	if (!agent) return 0;

	struct oknek_event *e = bpf_ringbuf_reserve(&oknek_events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e));
		e->ts_ns = bpf_ktime_get_ns();
		e->pid = pid;
		e->rule = 19; e->verdict = 2;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		__builtin_memcpy(e->agent_id, agent, AGENT_LEN);
		bpf_ringbuf_submit(e, 0);
	}
	if (oknek_enforce) return -EPERM;
	return 0;
}
