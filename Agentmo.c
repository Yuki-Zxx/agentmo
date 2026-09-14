// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 agentmo. */
//
// Agentmo userspace control plane. Loads the BPF skeleton (setting the
// const-volatile config first), polls the ring buffer, runs the policy engine
// on each event, prints structured verdicts, and emits a safe-execution
// attestation on exit.
//
// Scope: pass the agent ROOT PID (the OpenClaw gateway pid) as argv[1]. Only
// that process and its fork-descendants are traced; everything else on the
// machine (condor daemons, systemd, VS Code, this monitor itself) is out of
// scope and never even generates an event.
//
// ===========================================================================
// v2 — FIELD SUFFICIENCY FIX
// ===========================================================================
// v1 shipped ts / open-flags / path2 / AT_REMOVEDIR across the kernel boundary
// and then threw them away in printf(). The resulting logs could not answer
// "when", "read or write", "renamed to what", "unlink or rmdir" — even though
// the data was already in userspace memory. v2 prints all of it, adds argv
// display (kernel capture lands in Agentmo.bpf.c), and makes every line
// machine-parseable so the L0/L1/L2 filter funnel can be REPLAYED OFFLINE from
// a single AM_ALL=1 capture instead of being assembled from separate runs.
//
// Output format (default, text):
//   +<rel_s> <VERDICT> <TYPE> pid= ppid= uid= comm= <type-specific k=v...>
// Every value is key=value; every path is quoted. No fixed-width padding, so
// awk/cut never mis-splits on a path containing spaces.
//
// Environment:
//   AM_ALL=1     print every traced action (SAFE included) — use this for the
//                single full-visibility capture that the funnel replays from
//   AM_JSON=1    emit JSONL instead of text (one JSON object per line)
//   AM_WALL=1    add absolute wall-clock time alongside the relative timestamp
//   AM_DPATH=1   resolve open() paths with bpf_d_path via security_file_open
//                instead of the raw syscall argument (needs the v2 .bpf.c)
//   AM_POLICY=…  policy file path (else argv[2], else "policy.conf")
//
// Usage:
//   sudo ./Agentmo <AGENT_ROOT_PID> [policy.conf]
//   e.g. GW=$(pgrep -f 'node.*openclaw.*gateway' | head -1)
//        AM_ALL=1 sudo -E ./Agentmo "$GW" policy.conf > agentmo_full.log

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "Agentmo.h"
#include "Agentmo.skel.h"

#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif

/* ============================================================================
 * DEFAULT-DENY policy, driven by an EXTERNAL config file (no hardcoded rules).
 * Every agent-subtree action is AGENT_OP (out of policy) unless a loaded allow
 * rule matches. Config path: argv[2], or $AM_POLICY, or "policy.conf".
 * A missing file => empty allow-list => everything stays AGENT_OP.
 *
 * policy.conf format (one rule per line; '#' = comment, blank lines ok):
 *     read   /usr/lib               # path PREFIX: reads under here allowed
 *     write  /home/ubuntu/experiment/
 *     exec   /usr/bin/git           # FULL PATH (or a '/'-terminated prefix)
 *     net    192.168.0.0/16         # CIDR: connect into this range allowed
 * ============================================================================ */
#define MAXRULES 1024
static char rd_ok[MAXRULES][256]; static int n_rd;
static char wr_ok[MAXRULES][256]; static int n_wr;
static char ex_ok[MAXRULES][256]; static int n_ex;
static struct { unsigned int net, mask; } nt_ok[256]; static int n_nt;

static int pref_in(const char *p, char list[][256], int n)
{
	if (!p || !p[0]) return 0;         /* empty path can never match a prefix */
	for (int i = 0; i < n; i++)
		if (strncmp(p, list[i], strlen(list[i])) == 0) return 1;
	return 0;
}
/* exec allow-list, matched on the FULL PATH.
 *
 * v1 matched the BASENAME, which is a hole, not a convenience: `exec node`
 * would equally allow /tmp/node and ~/bin/node, and the agent can write its
 * own directory and edit PATH/.bashrc. A PATH-hijack would have been hidden
 * by the very rule meant to describe normal behaviour (MDX_DEPLOY.md 5.1).
 * Same defect class as OpenClaw's command-name allow-list: a legal NAME is
 * not a legal OBJECT.
 *
 * Rule ending in '/' = directory prefix (exec /usr/bin/ allows everything
 * under /usr/bin/). Otherwise the rule must equal the path exactly.
 * A relative exec path can never match a rule and stays AGENT_OP by
 * construction — that is intentional, and it is counted in the path-quality
 * self-report rather than quietly allowed. */
static int exec_ok(const char *p)
{
	if (!p || p[0] != '/') return 0;
	for (int i = 0; i < n_ex; i++) {
		size_t l = strlen(ex_ok[i]);
		if (!l) continue;
		if (ex_ok[i][l - 1] == '/') {          /* directory prefix */
			if (strncmp(p, ex_ok[i], l) == 0) return 1;
		} else if (strcmp(p, ex_ok[i]) == 0) { /* exact binary      */
			return 1;
		}
	}
	return 0;
}
static int net_allowed(unsigned int daddr_net)
{
	unsigned int a = ntohl(daddr_net);
	for (int i = 0; i < n_nt; i++)
		if ((a & nt_ok[i].mask) == nt_ok[i].net) return 1;
	return 0;
}

static void load_policy(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "[policy] cannot open '%s' -> allow-list EMPTY (all ops = AGENT_OP)\n", path);
		return;
	}
	char line[600];
	while (fgets(line, sizeof line, f)) {
		char kind[32], val[512];
		if (line[0] == '#' || line[0] == '\n') continue;
		if (sscanf(line, "%31s %511s", kind, val) != 2) continue;
		if      (!strcmp(kind, "read")  && n_rd < MAXRULES) snprintf(rd_ok[n_rd++], sizeof rd_ok[0], "%.*s", (int)sizeof(rd_ok[0]) - 1, val);
		else if (!strcmp(kind, "write") && n_wr < MAXRULES) snprintf(wr_ok[n_wr++], sizeof wr_ok[0], "%.*s", (int)sizeof(wr_ok[0]) - 1, val);
		else if (!strcmp(kind, "exec")  && n_ex < MAXRULES) snprintf(ex_ok[n_ex++], sizeof ex_ok[0], "%.*s", (int)sizeof(ex_ok[0]) - 1, val);
		else if (!strcmp(kind, "net")   && n_nt < 256) {
			unsigned int a, b, c, d, p = 32;
			if (sscanf(val, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &p) >= 4) {
				unsigned int ip = (a << 24) | (b << 16) | (c << 8) | d;
				unsigned int m  = (p == 0) ? 0u : (0xFFFFFFFFu << (32 - p));
				nt_ok[n_nt].mask = m; nt_ok[n_nt].net = ip & m; n_nt++;
			}
		}
	}
	fclose(f);
	fprintf(stderr, "[policy] loaded from %s: read=%d write=%d exec=%d net=%d\n",
		path, n_rd, n_wr, n_ex, n_nt);
}

/* ============================================================================
 * open() flag decoding — the field v1 captured but never printed, which is why
 * no log so far can tell a READ from a WRITE.
 * O_* values are ARCH-DEPENDENT (O_DIRECTORY differs on aarch64 vs x86), so we
 * use <fcntl.h> symbols rather than hardcoded octal.
 * ========================================================================== */
static void apnd(char *b, size_t n, size_t *o, const char *s)
{
	if (*o >= n - 1) return;
	size_t r = n - 1 - *o, l = strlen(s);
	if (l > r) l = r;
	memcpy(b + *o, s, l);
	*o += l;
	b[*o] = '\0';
}

static const char *oflags_str(int f, char *b, size_t n)
{
	size_t o = 0;
	b[0] = '\0';
	int acc = f & O_ACCMODE;
	apnd(b, n, &o, acc == O_RDONLY ? "O_RDONLY" :
		      acc == O_WRONLY ? "O_WRONLY" :
		      acc == O_RDWR   ? "O_RDWR"   : "O_ACC?");
#define AF(bit, name) do { if (f & (bit)) { apnd(b, n, &o, "|"); apnd(b, n, &o, name); } } while (0)
	AF(O_CREAT,     "O_CREAT");
	AF(O_EXCL,      "O_EXCL");
	AF(O_TRUNC,     "O_TRUNC");
	AF(O_APPEND,    "O_APPEND");
	AF(O_DIRECTORY, "O_DIRECTORY");
	AF(O_NOFOLLOW,  "O_NOFOLLOW");
	AF(O_CLOEXEC,   "O_CLOEXEC");
	AF(O_NONBLOCK,  "O_NONBLOCK");
#ifdef O_PATH
	AF(O_PATH,      "O_PATH");
#endif
#ifdef O_DIRECT
	AF(O_DIRECT,    "O_DIRECT");
#endif
#undef AF
	return b;
}

/* Is this open a WRITE-intent open? (v1 tested `f & 3 | O_CREAT | O_TRUNC`;
 * O_APPEND was missing.) */
static int open_is_write(int f)
{
	int acc = f & O_ACCMODE;
	return acc == O_WRONLY || acc == O_RDWR ||
	       (f & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

/* DEFAULT-DENY engine: V_SAFE only on an allow-rule hit; else V_ALERT. */
static int classify(const struct event *e)
{
	if (e->verdict == V_ALERT) return V_ALERT;   /* kernel always-violation set */
	switch (e->type) {
	case EV_FORK:                                /* process bookkeeping, not a resource op */
		return V_SAFE;
	case EV_EXEC:
		return exec_ok(e->path) ? V_SAFE : V_ALERT;
	case EV_OPEN:
		return open_is_write(e->arg1)
			? (pref_in(e->path, wr_ok, n_wr) ? V_SAFE : V_ALERT)
			: (pref_in(e->path, rd_ok, n_rd) ? V_SAFE : V_ALERT);
	case EV_DEL: case EV_REN: case EV_PERM: case EV_MKDIR:
		return pref_in(e->path, wr_ok, n_wr) ? V_SAFE : V_ALERT;
	case EV_NET:
		return net_allowed(e->daddr) ? V_SAFE : V_ALERT;
	default:                                     /* KILL/PTRACE/PRIV/NS/MOD/BPF/unknown */
		return V_ALERT;                      /* <-- default DENY */
	}
}

/* ============================================================================
 * Clock. bpf_ktime_get_ns() is CLOCK_MONOTONIC, so we snapshot both clocks at
 * startup: rel = ev.ts - mono0 (what you need for rates and durations), and
 * wall = ev.ts + (real0 - mono0) (what you need to line up with other logs).
 * ========================================================================== */
static unsigned long long mono0_ns;
static long long          wall_off_ns;

static void clock_init(void)
{
	struct timespec m, r;
	clock_gettime(CLOCK_MONOTONIC, &m);
	clock_gettime(CLOCK_REALTIME,  &r);
	mono0_ns    = (unsigned long long)m.tv_sec * 1000000000ULL + (unsigned long long)m.tv_nsec;
	wall_off_ns = ((long long)r.tv_sec * 1000000000LL + (long long)r.tv_nsec) - (long long)mono0_ns;
}
static double rel_s(unsigned long long ts)
{
	return ((double)((long long)ts - (long long)mono0_ns)) / 1e9;
}
static void wall_str(unsigned long long ts, char *b, size_t n)
{
	long long w = (long long)ts + wall_off_ns;
	time_t sec  = (time_t)(w / 1000000000LL);
	long   nsec = (long)(w % 1000000000LL);
	struct tm tm;
	localtime_r(&sec, &tm);
	size_t k = strftime(b, n, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(b + k, n - k, ".%06ld", nsec / 1000);
}

/* ============================================================================
 * Quoting / escaping. Paths and argv can contain spaces, quotes and newlines;
 * v1's fixed-width unquoted output is exactly why offline parsing kept
 * mis-splitting. Everything printed as a value goes through here.
 * ========================================================================== */
static void esc(const char *s, char *b, size_t n)
{
	size_t o = 0;
	for (; s && *s && o + 2 < n; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\')      { b[o++] = '\\'; b[o++] = (char)c; }
		else if (c == '\n')             { if (o + 3 >= n) break; b[o++] = '\\'; b[o++] = 'n'; }
		else if (c == '\t')             { if (o + 3 >= n) break; b[o++] = '\\'; b[o++] = 't'; }
		else if (c < 0x20 || c == 0x7f) { if (o + 7 >= n) break; o += (size_t)snprintf(b + o, n - o, "\\u%04x", c); }
		else                            { b[o++] = (char)c; }
	}
	b[o] = '\0';
}

/* args[] holds `argsnum` NUL-terminated strings packed back to back, using
 * `argslen` bytes. Render as a JSON-style array so it is unambiguous in BOTH
 * text and JSON mode: ["sed","-i","s/a/b/","f.yml"] */
static void args_array(const struct event *e, char *out, size_t n)
{
	size_t o = 0;
	char q[AM_ARGS_MAX * 2 + 8];
	out[0] = '\0';
	apnd(out, n, &o, "[");
	unsigned int len = e->argslen;
	if (len > AM_ARGS_MAX) len = AM_ARGS_MAX;
	unsigned int i = 0, k = 0;
	while (i < len && k < e->argsnum) {
		const char *a = e->args + i;
		size_t alen = strnlen(a, (size_t)(len - i));
		if (k) apnd(out, n, &o, ",");
		esc(a, q, sizeof q);
		apnd(out, n, &o, "\"");
		apnd(out, n, &o, q);
		apnd(out, n, &o, "\"");
		i += (unsigned int)alen + 1;
		k++;
	}
	apnd(out, n, &o, "]");
}

/* ============================================================================
 * Counters — including the FIELD SUFFICIENCY self-report. The monitor must be
 * able to state how much of its own output is unusable; that number is the
 * answer to "print out している情報は十分か".
 * ========================================================================== */
static unsigned long n_events, n_watch, n_alert, n_safe;
static unsigned long n_bytype[EV__MAX];
static unsigned long p_abs, p_rel, p_none, p_dpath;   /* path quality (OPEN/DEL/REN/PERM/EXEC) */
static unsigned long a_with, a_without, a_trunc;      /* argv coverage (EXEC only) */
static unsigned long long ts_first, ts_last;

static volatile int stop;
static int print_all, json_mode, wall_mode;
static void on_sig(int s) { (void)s; stop = 1; }

static const char *tname(unsigned t)
{
	static const char *n[] = { "?","EXEC","FORK","OPEN","DEL","REN","PERM",
				   "PRIV","NET","KILL","PTRACE","NS","MOD","BPF",
				   "MKDIR" };
	return (t < sizeof(n)/sizeof(n[0])) ? n[t] : "?";
}
/* Does this event type carry a filesystem path we should score for quality? */
static int type_has_path(unsigned t)
{
	return t == EV_EXEC || t == EV_OPEN || t == EV_DEL || t == EV_REN ||
	       t == EV_PERM || t == EV_MOD  || t == EV_MKDIR;
}

static int handle(void *ctx, void *data, size_t sz)
{
	(void)ctx; (void)sz;
	const struct event *e = data;
	int v = classify(e);
	const char *vs = (v == V_SAFE) ? "SAFE" : "AGENT_OP";

	n_events++;
	if (v == V_ALERT)      n_alert++;
	else if (v == V_WATCH) n_watch++;
	else                   n_safe++;
	if (e->type < EV__MAX) n_bytype[e->type]++;
	if (!ts_first) ts_first = e->ts;
	ts_last = e->ts;

	/* ---- field-sufficiency accounting ---- */
	if (type_has_path(e->type)) {
		if (!e->path[0])            p_none++;
		else if (e->path[0] == '/') p_abs++;
		else                        p_rel++;
		if (e->eflags & AM_EF_DPATH) p_dpath++;
	}
	if (e->type == EV_EXEC) {
		if (e->argsnum) a_with++; else a_without++;
		if (e->eflags & AM_EF_ARGS_TRUNC) a_trunc++;
	}

	if (!(v > V_SAFE || print_all))
		return 0;

	/* ---- build the type-specific fields ---- */
	char epath[MAX_PATH * 2 + 8], epath2[MAX_PATH * 2 + 8], ecomm[TASK_COMM_LEN * 2 + 8];
	char fl[160], argsbuf[AM_ARGS_MAX * 3 + 64], extra[AM_ARGS_MAX * 3 + 512];
	extra[0] = '\0';
	esc(e->comm,  ecomm,  sizeof ecomm);
	esc(e->path,  epath,  sizeof epath);
	esc(e->path2, epath2, sizeof epath2);

	switch (e->type) {
	case EV_OPEN:
		snprintf(extra, sizeof extra, " rw=%c flags=%s",
			 open_is_write(e->arg1) ? 'W' : 'R',
			 oflags_str(e->arg1, fl, sizeof fl));
		break;
	case EV_EXEC:
		args_array(e, argsbuf, sizeof argsbuf);
		snprintf(extra, sizeof extra, " argc=%u argv=%s%s",
			 e->argsnum, argsbuf,
			 (e->eflags & AM_EF_ARGS_TRUNC) ? " argv_trunc=1" : "");
		break;
	case EV_DEL:
		snprintf(extra, sizeof extra, " op=%s",
			 (e->arg2 & AT_REMOVEDIR) ? "rmdir" : "unlink");
		break;
	case EV_REN:
		snprintf(extra, sizeof extra, " path2=\"%s\"", epath2);
		break;
	case EV_PERM:
		if (e->eflags & AM_EF_PERM_OWN)
			snprintf(extra, sizeof extra, " op=chown owner=%d group=%d", e->arg1, e->arg2);
		else
			snprintf(extra, sizeof extra, " op=chmod mode=0%o", (unsigned)e->arg1 & 07777);
		break;
	case EV_PRIV:
		snprintf(extra, sizeof extra, " setuid=%d", e->arg1);
		break;
	case EV_NET: {
		struct in_addr in = { .s_addr = e->daddr };
		snprintf(extra, sizeof extra, " dst=%s port=%d", inet_ntoa(in), e->arg1);
		break;
	}
	case EV_KILL:
		snprintf(extra, sizeof extra, " target=%d signal=%d", e->arg1, e->arg2);
		break;
	case EV_PTRACE:
		snprintf(extra, sizeof extra, " request=%d target=%d", e->arg1, e->arg2);
		break;
	case EV_FORK:
		snprintf(extra, sizeof extra, " child=%d", e->arg1);
		break;
	case EV_MKDIR:
		snprintf(extra, sizeof extra, " op=mkdir mode=0%o", (unsigned)e->arg1 & 07777);
		break;
	case EV_BPF:
		snprintf(extra, sizeof extra, " cmd=%d", e->arg1);
		break;
	default:
		break;
	}

	char wall[48] = "";
	if (wall_mode) wall_str(e->ts, wall, sizeof wall);

	if (json_mode) {
		/* JSONL: one object per line. This is what the offline funnel
		 * replay (L0 -> L1 -> L2 from ONE capture) consumes. */
		printf("{\"t\":%.6f", rel_s(e->ts));
		if (wall_mode) printf(",\"wall\":\"%s\"", wall);
		printf(",\"verdict\":\"%s\",\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u"
		       ",\"comm\":\"%s\",\"path\":\"%s\",\"path_kind\":\"%s\",\"src\":\"%s\"",
		       vs, tname(e->type), e->pid, e->ppid, e->uid, ecomm, epath,
		       !e->path[0] ? "none" : (e->path[0] == '/' ? "abs" : "rel"),
		       (e->eflags & AM_EF_DPATH) ? "d_path" : "syscall");
		switch (e->type) {
		case EV_OPEN:
			printf(",\"rw\":\"%c\",\"flags\":\"%s\",\"flags_raw\":%d",
			       open_is_write(e->arg1) ? 'W' : 'R',
			       oflags_str(e->arg1, fl, sizeof fl), e->arg1);
			break;
		case EV_EXEC:
			args_array(e, argsbuf, sizeof argsbuf);
			printf(",\"argc\":%u,\"argv\":%s,\"argv_trunc\":%d",
			       e->argsnum, argsbuf, (e->eflags & AM_EF_ARGS_TRUNC) ? 1 : 0);
			break;
		case EV_DEL:
			printf(",\"op\":\"%s\"", (e->arg2 & AT_REMOVEDIR) ? "rmdir" : "unlink");
			break;
		case EV_REN:
			printf(",\"path2\":\"%s\"", epath2);
			break;
		case EV_PERM:
			if (e->eflags & AM_EF_PERM_OWN)
				printf(",\"op\":\"chown\",\"owner\":%d,\"group\":%d", e->arg1, e->arg2);
			else
				printf(",\"op\":\"chmod\",\"mode\":\"0%o\"", (unsigned)e->arg1 & 07777);
			break;
		case EV_PRIV:  printf(",\"setuid\":%d", e->arg1); break;
		case EV_NET: {
			struct in_addr in = { .s_addr = e->daddr };
			printf(",\"dst\":\"%s\",\"port\":%d", inet_ntoa(in), e->arg1);
			break;
		}
		case EV_KILL:   printf(",\"target\":%d,\"signal\":%d", e->arg1, e->arg2); break;
		case EV_PTRACE: printf(",\"request\":%d,\"target\":%d", e->arg1, e->arg2); break;
		case EV_FORK:   printf(",\"child\":%d", e->arg1); break;
		case EV_MKDIR:  printf(",\"op\":\"mkdir\",\"mode\":\"0%o\"", (unsigned)e->arg1 & 07777); break;
		case EV_BPF:    printf(",\"cmd\":%d", e->arg1); break;
		default: break;
		}
		printf("}\n");
	} else {
		printf("%+14.6f %-8s %-6s pid=%u ppid=%u uid=%u comm=\"%s\" path=\"%s\"%s%s%s\n",
		       rel_s(e->ts), vs, tname(e->type), e->pid, e->ppid, e->uid,
		       ecomm, epath, extra,
		       (e->eflags & AM_EF_DPATH) ? " src=d_path" : "",
		       wall_mode ? wall : "");
	}
	return 0;
}

static void report(void)
{
	double dur = (ts_first && ts_last > ts_first) ? (double)(ts_last - ts_first) / 1e9 : 0.0;

	fprintf(stderr, "\n==== EXECUTION ATTESTATION ====\n");
	fprintf(stderr, "duration(first..last event) = %.3f s\n", dur);
	fprintf(stderr, "events = %lu   safe=%lu watch=%lu alert=%lu", n_events, n_safe, n_watch, n_alert);
	if (dur > 0) fprintf(stderr, "   rate=%.1f ev/s", n_events / dur);
	fprintf(stderr, "\nby type:");
	for (unsigned t = 1; t < EV__MAX; t++)
		if (n_bytype[t]) fprintf(stderr, "  %s=%lu", tname(t), n_bytype[t]);
	fprintf(stderr, "\n");

	/* ---- the number the sensei discussion needs ---- */
	unsigned long pt = p_abs + p_rel + p_none;
	fprintf(stderr, "\n---- FIELD SUFFICIENCY SELF-REPORT ----\n");
	if (pt) {
		fprintf(stderr, "path-bearing events = %lu\n", pt);
		fprintf(stderr, "  absolute  = %-8lu (%5.2f%%)   <- resolvable to a file\n",
			p_abs,  100.0 * (double)p_abs  / (double)pt);
		fprintf(stderr, "  relative  = %-8lu (%5.2f%%)   <- basename only, NOT resolvable\n",
			p_rel,  100.0 * (double)p_rel  / (double)pt);
		fprintf(stderr, "  missing   = %-8lu (%5.2f%%)\n",
			p_none, 100.0 * (double)p_none / (double)pt);
		fprintf(stderr, "  of which resolved by bpf_d_path = %lu\n", p_dpath);
	} else {
		fprintf(stderr, "path-bearing events = 0\n");
	}
	unsigned long ex = a_with + a_without;
	fprintf(stderr, "exec events = %lu   with argv = %lu   without argv = %lu   truncated = %lu\n",
		ex, a_with, a_without, a_trunc);
	if (p_rel || p_none || a_without)
		fprintf(stderr, ">> NOTE: %lu event(s) carry no resolvable path and %lu exec(s) carry no argv.\n"
				">>       Those actions were DETECTED but cannot be RECONSTRUCTED.\n",
			p_rel + p_none, a_without);

	fprintf(stderr, "\n%s", n_alert == 0
		? ">> VERDICT: SAFE — execution stayed within the declared safe envelope\n"
		: "");
	if (n_alert) fprintf(stderr, ">> VERDICT: UNSAFE — %lu out-of-envelope action(s) detected\n", n_alert);
}

int main(int argc, char **argv)
{
	struct Agentmo_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s <AGENT_ROOT_PID> [policy.conf]\n"
			"  e.g. GW=$(pgrep -f 'node.*openclaw.*gateway' | head -1); sudo %s $GW policy.conf\n"
			"  env: AM_ALL=1 AM_JSON=1 AM_WALL=1 AM_DPATH=1 AM_POLICY=<file>\n",
			argv[0], argv[0]);
		return 2;
	}
	unsigned int root = (unsigned int)strtoul(argv[1], NULL, 10);
	if (!root) { fprintf(stderr, "invalid pid: %s\n", argv[1]); return 2; }

	const char *polpath = (argc >= 3) ? argv[2]
			    : (getenv("AM_POLICY") ? getenv("AM_POLICY") : "policy.conf");
	load_policy(polpath);

	print_all = (getenv("AM_ALL")  != NULL);
	json_mode = (getenv("AM_JSON") != NULL);
	wall_mode = (getenv("AM_WALL") != NULL);
	int use_dpath = (getenv("AM_DPATH") != NULL);

	clock_init();
	signal(SIGINT,  on_sig);
	signal(SIGTERM, on_sig);

	skel = Agentmo_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }

	/* Configure the kernel object before load (writes .rodata). */
	skel->rodata->target_pid = root;             /* scope = this pid's subtree */
	skel->rodata->enforce_mode = 0;              /* observe only */
	skel->rodata->policy_features = 0xffffffff;  /* all categories */

	/* AM_DPATH=1 swaps the open() capture point:
	 *   off -> tp/syscalls/sys_enter_openat  : raw syscall arg (relative paths
	 *          stay relative — this is why `find`/`grep` produced 260k
	 *          basename-only events)
	 *   on  -> fentry/security_file_open     : bpf_d_path() gives the RESOLVED
	 *          absolute path, at the cost of an unstable-ABI attach point and
	 *          losing failed opens (security_file_open only fires on success).
	 * Running the same workload both ways is the experiment that quantifies
	 * "which layer do you have to hook to get a usable path". */
#ifdef AM_HAVE_DPATH_PROG
	bpf_program__set_autoload(skel->progs.on_openat,    !use_dpath);
	bpf_program__set_autoload(skel->progs.on_file_open,  use_dpath);
#else
	if (use_dpath)
		fprintf(stderr, "[warn] AM_DPATH=1 ignored: this build has no "
				"security_file_open program (update Agentmo.bpf.c, "
				"then compile with -DAM_HAVE_DPATH_PROG)\n");
#endif

	if ((err = Agentmo_bpf__load(skel)))   { fprintf(stderr, "load %d\n", err);   goto out; }
	if ((err = Agentmo_bpf__attach(skel))) { fprintf(stderr, "attach %d\n", err); goto out; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf new failed\n"); err = 1; goto out; }

	fprintf(stderr, ">> Agentmo running: scope=pid %u subtree | %s | %s | open-src=%s (Ctrl-C to stop)\n",
		root,
		print_all ? "print-ALL" : "anomaly-only",
		json_mode ? "JSONL" : "text",
		use_dpath ? "security_file_open+d_path" : "sys_enter_openat");

	while (!stop) {
		err = ring_buffer__poll(rb, 200);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "poll err %d\n", err); break; }
	}

	fflush(stdout);
	report();

out:
	ring_buffer__free(rb);
	Agentmo_bpf__destroy(skel);
	return err ? 1 : 0;
}
