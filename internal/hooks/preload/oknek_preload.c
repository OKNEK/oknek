/* oknek_preload.c — oknek interposition shim.
 *
 * Interposes libc open/openat (Task 3) and later execve/connect (Task 5).
 * On each call it asks the running oknekd over the local Unix socket and,
 * on a "block" verdict, refuses the action (errno=EACCES, return -1) before
 * the real syscall ever runs.
 *
 * Build: cc -shared -fPIC -o liboknek_preload.{so,dylib} oknek_preload.c -ldl
 * Use (Linux):  LD_PRELOAD=...            OKNEK_SOCK=... OKNEK_AGENT=...
 * Use (macOS):  DYLD_INSERT_LIBRARIES=... OKNEK_SOCK=... OKNEK_AGENT=...
 *
 * Resolving the real libc function differs by platform:
 *   - Linux: dlsym(RTLD_NEXT, "name") finds the next definition after us.
 *   - macOS: dyld's __interpose excludes the interposing library's own
 *     references, so calling the symbol by name reaches the real libc.
 *     (dlsym(RTLD_NEXT,...) is unreliable here and was crashing.)
 *
 * Fail-open: any error reaching the daemon lets the action proceed. The shim
 * must never brick the host process; it only ever blocks on an explicit
 * "block" verdict.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

/* Our defensive NULL checks on libc params that are declared nonnull are
 * intentional (an interposer must never crash the host); silence gcc's
 * -Wnonnull-compare for them. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wnonnull-compare"
#endif

#ifdef __APPLE__
/* Call the real libc function by name; dyld interpose self-exclusion applies. */
#define REAL(name) name
#else
/* Resolve and cache the next definition with dlsym. */
#define REAL(name) ({ \
	static typeof(&name) _p; \
	if (!_p) _p = (typeof(&name))dlsym(RTLD_NEXT, #name); \
	_p; })
#endif

/* Re-entrancy guard: the shim itself opens sockets; never gate that work. */
static __thread int oknek_in = 0;

static const char *oknek_sock(void) {
	const char *s = getenv("OKNEK_SOCK");
	if (s && *s) return s;
	return "/run/oknek/oknek.sock";
}

static const char *oknek_agent(void) {
	const char *a = getenv("OKNEK_AGENT");
	return (a && *a) ? a : "agent";
}

/* ── hostname cache (resolved IP string → queried hostname) ──────────────────
 *
 * getaddrinfo() learns the hostname an agent asked for; connect() only sees the
 * resolved IP. We bridge them with a small, bounded, mutex-guarded table so the
 * R10 route-around detector can match on the dest *host* (suffix match) rather
 * than a bare IP. FIFO overwrite when full — recency over completeness; a miss
 * just falls back to the IP string (detector then fails open on that event). */
#define OKNEK_HOSTCACHE_N 256
#define OKNEK_IP_MAX      64
#define OKNEK_HOST_MAX    256

struct oknek_hostent {
	char ip[OKNEK_IP_MAX];
	char host[OKNEK_HOST_MAX];
};
static struct oknek_hostent oknek_hostcache[OKNEK_HOSTCACHE_N];
static int oknek_hostcache_next = 0; /* FIFO write cursor */
static pthread_mutex_t oknek_hostcache_mu = PTHREAD_MUTEX_INITIALIZER;

/* Insert/refresh ip→host. No-ops on bad input; never blocks the host app. */
static void oknek_hostcache_put(const char *ip, const char *host) {
	if (!ip || !*ip || !host || !*host) return;
	pthread_mutex_lock(&oknek_hostcache_mu);
	/* Refresh an existing entry for this IP if present, else FIFO-append. */
	int slot = -1;
	for (int i = 0; i < OKNEK_HOSTCACHE_N; i++) {
		if (oknek_hostcache[i].ip[0] && strcmp(oknek_hostcache[i].ip, ip) == 0) { slot = i; break; }
	}
	if (slot < 0) {
		slot = oknek_hostcache_next;
		oknek_hostcache_next = (oknek_hostcache_next + 1) % OKNEK_HOSTCACHE_N;
	}
	strncpy(oknek_hostcache[slot].ip, ip, OKNEK_IP_MAX - 1);
	oknek_hostcache[slot].ip[OKNEK_IP_MAX - 1] = 0;
	strncpy(oknek_hostcache[slot].host, host, OKNEK_HOST_MAX - 1);
	oknek_hostcache[slot].host[OKNEK_HOST_MAX - 1] = 0;
	pthread_mutex_unlock(&oknek_hostcache_mu);
}

/* Copy the cached hostname for ip into out (cap n); on miss copy ip itself.
 * Always leaves out NUL-terminated (when n>0). */
static void oknek_hostcache_get(const char *ip, char *out, size_t n) {
	if (!out || n == 0) return;
	out[0] = 0;
	const char *fallback = (ip && *ip) ? ip : "";
	if (!ip || !*ip) { return; }
	pthread_mutex_lock(&oknek_hostcache_mu);
	const char *found = NULL;
	for (int i = 0; i < OKNEK_HOSTCACHE_N; i++) {
		if (oknek_hostcache[i].ip[0] && strcmp(oknek_hostcache[i].ip, ip) == 0) {
			found = oknek_hostcache[i].host; break;
		}
	}
	strncpy(out, found ? found : fallback, n - 1);
	out[n - 1] = 0;
	pthread_mutex_unlock(&oknek_hostcache_mu);
}

/* ── cached process identity (pid/ppid/name) ────────────────────────────────
 *
 * Resolved once per process and reused, so connect() can attribute a
 * route-around to the real agent process. Best-effort: any failure leaves the
 * name "unknown" and never affects the host call. */
static int  oknek_self_pid  = 0;
static int  oknek_self_ppid = 0;
static char oknek_self_comm[OKNEK_HOST_MAX] = "unknown";
static pthread_once_t oknek_self_once = PTHREAD_ONCE_INIT;

static void oknek_self_init(void) {
	oknek_self_pid  = (int)getpid();
	oknek_self_ppid = (int)getppid();
#if defined(__APPLE__)
	char path[1024];
	uint32_t sz = sizeof path;
	if (_NSGetExecutablePath(path, &sz) == 0) {
		const char *base = strrchr(path, '/');
		base = base ? base + 1 : path;
		if (*base) {
			strncpy(oknek_self_comm, base, sizeof(oknek_self_comm) - 1);
			oknek_self_comm[sizeof(oknek_self_comm) - 1] = 0;
		}
	}
#else
	int fd = REAL(open)("/proc/self/comm", O_RDONLY);
	if (fd >= 0) {
		char buf[OKNEK_HOST_MAX];
		ssize_t n = REAL(read)(fd, buf, sizeof(buf) - 1);
		REAL(close)(fd);
		if (n > 0) {
			buf[n] = 0;
			char *nl = strchr(buf, '\n');
			if (nl) *nl = 0;
			if (buf[0]) {
				strncpy(oknek_self_comm, buf, sizeof(oknek_self_comm) - 1);
				oknek_self_comm[sizeof(oknek_self_comm) - 1] = 0;
			}
		}
	}
#endif
}

static void oknek_self(int *pid, int *ppid, const char **comm) {
	pthread_once(&oknek_self_once, oknek_self_init);
	if (pid)  *pid  = oknek_self_pid;
	if (ppid) *ppid = oknek_self_ppid;
	if (comm) *comm = oknek_self_comm;
}

/* Minimal JSON string escaper into out (size cap). Escapes " \ and controls. */
static void json_escape(const char *in, char *out, size_t cap) {
	size_t o = 0;
	for (size_t i = 0; in[i] && o + 2 < cap; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
		else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
		else if (c == '\t') { out[o++] = '\\'; out[o++] = 't'; }
		else if (c < 0x20) { /* drop other control chars */ }
		else { out[o++] = c; }
	}
	out[o] = 0;
}

/* Send one JSON request line to oknekd, read one response line.
 * Returns 1 iff the response contains a "block" verdict; 0 otherwise
 * (including every error path — fail-open). */
static int oknek_query(const char *json) {
	int fd = REAL(socket)(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return 0;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, oknek_sock(), sizeof(addr.sun_path) - 1);
	if (REAL(connect)(fd, (struct sockaddr *)&addr, sizeof addr) != 0) { REAL(close)(fd); return 0; }

	size_t len = strlen(json);
	if (REAL(write)(fd, json, len) < 0) { REAL(close)(fd); return 0; }
	if (len == 0 || json[len - 1] != '\n') { if (REAL(write)(fd, "\n", 1) < 0) { /* ignore */ } }

	char buf[8192];
	ssize_t n = REAL(read)(fd, buf, sizeof(buf) - 1);
	REAL(close)(fd);
	if (n <= 0) return 0;
	buf[n] = 0;
	return strstr(buf, "\"verdict\":\"block\"") != NULL;
}

static void oknek_loud_block(const char *what, const char *detail) {
	fprintf(stderr, "\n[oknek] BLOCK %s :: %s :: action denied (errno=EACCES)\n", what, detail);
}

/* Announce the shim to oknekd once at library load, so `status` reports the
 * real hook mode + a watched agent. Fail-open: ignored if the daemon is down. */
__attribute__((constructor))
static void oknek_attach(void) {
#ifdef __APPLE__
	const char *mode = "dyld";
#else
	const char *mode = "ld_preload";
#endif
	char req[512];
	snprintf(req, sizeof req,
		"{\"method\":\"hook.attach\",\"params\":{\"mode\":\"%s\",\"agent_id\":\"%s\",\"pid\":%d}}",
		mode, oknek_agent(), (int)getpid());
	oknek_in = 1; /* never let attach re-enter our interposers */
	(void)oknek_query(req);
	oknek_in = 0;
}

/* ── interposers ─────────────────────────────────────────── */
#ifdef __APPLE__
#define OKNEK_FN(name) oknek_##name
#else
#define OKNEK_FN(name) name
#endif

int OKNEK_FN(open)(const char *path, int flags, ...) {
	mode_t mode = 0;
	if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
	if (oknek_in || !path) return REAL(open)(path, flags, mode);
	oknek_in = 1;
	char esc[3072], req[4096];
	json_escape(path, esc, sizeof esc);
	snprintf(req, sizeof req,
		"{\"method\":\"check.fileopen\",\"params\":{\"path\":\"%s\",\"mode\":\"read\",\"agent_id\":\"%s\"}}",
		esc, oknek_agent());
	int blocked = oknek_query(req);
	oknek_in = 0;
	if (blocked) { oknek_loud_block("open", path); errno = EACCES; return -1; }
	return REAL(open)(path, flags, mode);
}

int OKNEK_FN(openat)(int dirfd, const char *path, int flags, ...) {
	mode_t mode = 0;
	if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
	if (oknek_in || !path) return REAL(openat)(dirfd, path, flags, mode);
	oknek_in = 1;
	char esc[3072], req[4096];
	json_escape(path, esc, sizeof esc);
	snprintf(req, sizeof req,
		"{\"method\":\"check.fileopen\",\"params\":{\"path\":\"%s\",\"mode\":\"read\",\"agent_id\":\"%s\"}}",
		esc, oknek_agent());
	int blocked = oknek_query(req);
	oknek_in = 0;
	if (blocked) { oknek_loud_block("openat", path); errno = EACCES; return -1; }
	return REAL(openat)(dirfd, path, flags, mode);
}

int OKNEK_FN(execve)(const char *path, char *const argv[], char *const envp[]) {
	if (oknek_in || !path) return REAL(execve)(path, argv, envp);
	/* Reconstruct the command line for R1 chain-depth analysis. */
	char cmd[4096]; size_t o = 0; cmd[0] = 0;
	for (int i = 0; argv && argv[i] && o + 1 < sizeof cmd; i++) {
		size_t l = strlen(argv[i]);
		if (o + l + 2 >= sizeof cmd) break;
		if (i) cmd[o++] = ' ';
		memcpy(cmd + o, argv[i], l); o += l; cmd[o] = 0;
	}
	oknek_in = 1;
	char esc[3072], req[4096];
	json_escape(cmd, esc, sizeof esc);
	snprintf(req, sizeof req,
		"{\"method\":\"check.exec\",\"params\":{\"command\":\"%s\",\"agent_id\":\"%s\"}}",
		esc, oknek_agent());
	int blocked = oknek_query(req);
	oknek_in = 0;
	if (blocked) { oknek_loud_block("execve", cmd); errno = EACCES; return -1; }
	return REAL(execve)(path, argv, envp);
}

int OKNEK_FN(connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	if (oknek_in || !addr) return REAL(connect)(sockfd, addr, addrlen);
	/* Only gate INET/INET6 egress; never gate our own AF_UNIX daemon socket. */
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		return REAL(connect)(sockfd, addr, addrlen);
	char host[64] = "0.0.0.0"; int port = 0;
	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &s->sin_addr, host, sizeof host);
		port = ntohs(s->sin_port);
	} else {
		const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &s->sin6_addr, host, sizeof host);
		port = ntohs(s->sin6_port);
	}
	oknek_in = 1;
	/* Resolve the dest host from the getaddrinfo cache (falls back to the IP
	 * string on a miss) and attribute the connect to this process, so the R10
	 * route-around detector can match on host + identify the agent. */
	char dest_host[OKNEK_HOST_MAX];
	oknek_hostcache_get(host, dest_host, sizeof dest_host);
	int self_pid = 0, self_ppid = 0; const char *self_comm = "unknown";
	oknek_self(&self_pid, &self_ppid, &self_comm);
	char esc_host[OKNEK_HOST_MAX * 2], esc_comm[OKNEK_HOST_MAX * 2];
	json_escape(dest_host, esc_host, sizeof esc_host);
	json_escape(self_comm, esc_comm, sizeof esc_comm);
	char req[640];
	snprintf(req, sizeof req,
		"{\"method\":\"check.socket\",\"params\":{\"dest_host\":\"%s\",\"dest_port\":%d,\"agent_id\":\"%s\",\"process\":\"%s\",\"pid\":%d,\"ppid\":%d}}",
		esc_host, port, oknek_agent(), esc_comm, self_pid, self_ppid);
	int blocked = oknek_query(req);
	oknek_in = 0;
	if (blocked) { oknek_loud_block("connect", host); errno = EACCES; return -1; }
	return REAL(connect)(sockfd, addr, addrlen);
}

/* getaddrinfo learns each hostname an agent resolves; we record every returned
 * INET/INET6 address → that hostname so connect() can recover the host from the
 * IP. We never gate or alter resolution: we always return the real rc/result,
 * and on any non-zero rc (or while re-entrant) we touch nothing. */
int OKNEK_FN(getaddrinfo)(const char *node, const char *service,
                          const struct addrinfo *hints, struct addrinfo **res) {
	int rc = REAL(getaddrinfo)(node, service, hints, res);
	if (rc != 0 || oknek_in || !node || !res || !*res) return rc;
	oknek_in = 1;
	for (struct addrinfo *ai = *res; ai; ai = ai->ai_next) {
		char ip[OKNEK_IP_MAX];
		ip[0] = 0;
		if (ai->ai_family == AF_INET && ai->ai_addr) {
			const struct sockaddr_in *s = (const struct sockaddr_in *)ai->ai_addr;
			inet_ntop(AF_INET, &s->sin_addr, ip, sizeof ip);
		} else if (ai->ai_family == AF_INET6 && ai->ai_addr) {
			const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)ai->ai_addr;
			inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof ip);
		} else {
			continue;
		}
		if (ip[0]) oknek_hostcache_put(ip, node);
	}
	oknek_in = 0;
	return rc;
}

#ifdef __APPLE__
/* dyld interpose registration (two-level namespace; self-references excluded). */
#define DYLD_INTERPOSE(_repl, _replee) \
	__attribute__((used)) static struct { const void *r; const void *e; } \
	_interpose_##_replee __attribute__((section("__DATA,__interpose"))) = \
	{ (const void *)(unsigned long)&_repl, (const void *)(unsigned long)&_replee };
DYLD_INTERPOSE(oknek_open, open)
DYLD_INTERPOSE(oknek_openat, openat)
DYLD_INTERPOSE(oknek_execve, execve)
DYLD_INTERPOSE(oknek_connect, connect)
DYLD_INTERPOSE(oknek_getaddrinfo, getaddrinfo)
#endif
