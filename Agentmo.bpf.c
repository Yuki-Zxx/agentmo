// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 agentmo. */
//
// Agentmo in-kernel data plane — v2 (2026-09-14, rewritten for mdx/x86_64).
//
// ===========================================================================
// WHAT CHANGED vs the 8/25 version (and WHY)
// ===========================================================================
// 1. SCOPE IS NOW A PROCESS SUBTREE, NOT A uid FILTER.
//    v1 filtered on `uid in {0,1000}`, which on this cluster matches condor
//    daemons, the VS Code server, sshd children — everything. v2 takes the
//    agent ROOT PID in `.rodata target_pid` (the OpenClaw gateway MainPID) and
//    tracks its fork-descendants in a hash map. This is the L1 filter that
//    MDX_DEPLOY.md §5 showed is the *only* thing that separates the gateway's
//    `MainThread` children from the VS Code server's identically-named ones.
//    CONSEQUENCE (operational discipline): a child that already existed before
//    Agentmo attached is NOT in the map and will be missed. Always
//    `systemctl --user restart openclaw` and start Agentmo BEFORE dispatching.
//
// 2. x86_64 LEGACY SYSCALL VARIANTS ARE NOW HOOKED.
//    MDX_DEPLOY.md §4 measured it: on x86_64 `python3 os.remove()` issues
//    `unlink`, while `rm` issues `unlinkat`. v1 hooked only the *at() forms
//    (correct on nodeA/arm64, where the legacy ones do not exist) and therefore
//    SILENTLY MISSED every Python-side delete on mdx. v2 hooks both families:
//      open   / openat / openat2 / creat
//      unlink / unlinkat / rmdir
//      rename / renameat / renameat2
//      chmod  / fchmod  / fchmodat
//      chown  / lchown  / fchown / fchownat
//      mkdir  / mkdirat
//    NOTE: the legacy tracepoints exist on x86_64 but NOT on arm64. This file
//    therefore builds/attaches on x86_64; see AM_LEGACY_SYSCALLS below if you
//    ever need to run it on nodeA again.
//
// 3. argv IS CAPTURED (AM_ARGS_MAX budget, execsnoop-style chunked copy).
//    v1 recorded that an exec happened but not *what command* — the logs could
//    not be replayed. Truncation is flagged (AM_EF_ARGS_TRUNC), never silent.
//
// 4. security_file_open + bpf_d_path (`on_file_open`) EXISTS NOW.
//    Agentmo.c v2 references `skel->progs.on_file_open` under
//    -DAM_HAVE_DPATH_PROG; without this program the build/AM_DPATH=1 path was
//    dead. Raw syscall args give you `find`-style relative paths; d_path gives
//    a resolved absolute path. Running the same workload both ways is the
//    measurement of "which layer must you hook to get a usable path".
//
// 5. fd-BASED VARIANTS ARE EMITTED WITH AN EMPTY PATH ON PURPOSE.
//    fchmod/fchown/fstat-family take an fd, not a path. We still emit the
//    event (so the action is DETECTED) with path="" (so it is counted as
//    "not reconstructable" in the field-sufficiency self-report). Hiding them
//    would understate the monitor's blind spot; that number is a deliverable.
//
// Policy/whitelist logic stays in userspace (observe mode). enforce_mode is
// wired but unused this round — see MDX_DEPLOY.md §3.4, security=full is kept.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "Agentmo.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ---------------------------------------------------------------------------
 * Configuration set by userspace in .rodata before load (BTF-typed globals).
 * Agentmo.c writes all three; keep the names in sync with it.
 * ------------------------------------------------------------------------- */
const volatile unsigned int target_pid      = 0;          /* agent root pid  */
const volatile unsigned int enforce_mode    = 0;          /* observe only    */
const volatile unsigned int policy_features = 0xffffffff; /* all categories  */

#include "Envelope.bpf.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif
/* x86_64 O_* — used only to synthesise flags for creat()/mkdir(). */
#define AM_O_WRONLY   00000001
#define AM_O_CREAT    00000100
#define AM_O_TRUNC    00001000
#define AM_O_DIRECTORY 00200000

#define FEAT(f) (policy_features & (f))

/* Build knob: set to 0 to drop the legacy (x86-only) syscall tracepoints so
 * the object also attaches on arm64. Leave at 1 for mdx. */
#ifndef AM_LEGACY_SYSCALLS
#define AM_LEGACY_SYSCALLS 1
#endif

/* ===========================================================================
 * L1 — process-subtree scope
 *
 * `tracked` holds every pid known to descend from target_pid. Membership is
 * established at fork time (sched_process_fork runs in the PARENT's context,
 * so we test the parent by its tgid — this is what makes thread-spawned
 * children of the node gateway visible; filtering on ctx->parent_pid would
 * miss anything forked from a `MainThread`).
 * ========================================================================= */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key,   __u32);
	__type(value, __u8);
} tracked SEC(".maps");

static __always_inline int am_pid_in_scope(__u32 pid)
{
	if (!target_pid)
		return 0;                     /* unconfigured => trace nothing */
	if (pid == target_pid)
		return 1;
	return bpf_map_lookup_elem(&tracked, &pid) != 0;
}

/* Scope test for the CURRENT task. Deliberately NOT combined with the uid
 * filter from Envelope.bpf.h: if the agent escalates to another uid we must
 * still see it — that escalation is precisely the event of interest. */
static __always_inline int am_scope(void)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	return am_pid_in_scope(tgid);
}

/* ===========================================================================
 * argv capture
 *
 * execsnoop's chunked pattern: a CONSTANT per-string read size plus a bound
 * check before each read is what keeps the verifier happy with a variable
 * destination offset. A variable-size read into args[off] does not verify.
 * ========================================================================= */
#define AM_ARG_CHUNK 128
#define AM_ARGS_LAST (AM_ARGS_MAX - AM_ARG_CHUNK)

static __always_inline void am_capture_argv(struct event *e,
					    const char *const *uargv)
{
	__u32 off = 0, n = 0;
	int i;

	if (!uargv)
		return;

	for (i = 0; i < AM_ARGS_NMAX; i++) {
		const char *p = 0;
		long r;

		if (bpf_probe_read_user(&p, sizeof(p), &uargv[i]) < 0)
			goto done;
		if (!p)                       /* NULL terminator: complete */
			goto done;
		if (off > AM_ARGS_LAST) {     /* no room for another chunk */
			e->eflags |= AM_EF_ARGS_TRUNC;
			goto done;
		}
		r = bpf_probe_read_user_str(&e->args[off], AM_ARG_CHUNK, p);
		if (r <= 0 || r > AM_ARG_CHUNK) {
			e->eflags |= AM_EF_ARGS_TRUNC;
			goto done;
		}
		off += (__u32)r;
		n++;
	}
	/* Fell out of the loop => there may be an argv[AM_ARGS_NMAX]. */
	{
		const char *p = 0;
		if (bpf_probe_read_user(&p, sizeof(p), &uargv[AM_ARGS_NMAX]) == 0 && p)
			e->eflags |= AM_EF_ARGS_TRUNC;
	}
done:
	e->argslen = off;
	e->argsnum = n;
}

/* Small helpers so every hook body stays three lines. */
static __always_inline struct event *am_ev(__u32 type, __u32 feat)
{
	if (!FEAT(feat) || !am_scope())
		return 0;
	return am_begin(type);
}
static __always_inline void am_upath(struct event *e, const void *uptr)
{
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (const char *)uptr);
}

/* ===========================================================================
 * 0. process tree  (registration point — must run before anything else)
 * ========================================================================= */
SEC("tp/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 ptgid = bpf_get_current_pid_tgid() >> 32;
	__u32 child = (__u32)ctx->child_pid;
	__u8 one = 1;
	struct event *e;

	if (!am_pid_in_scope(ptgid))
		return 0;

	bpf_map_update_elem(&tracked, &child, &one, BPF_ANY);

	e = am_begin(EV_FORK);
	if (!e)
		return 0;
	e->arg1 = (int)child;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Reap the map so a long run cannot exhaust it and so recycled pids do not
 * silently re-enter scope. Keyed on the exiting task's own pid (tid): a thread
 * exit removes its stray tid entry, a group-leader exit removes the process. */
SEC("tp/sched/sched_process_exit")
int on_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 pid = (__u32)ctx->pid;
	bpf_map_delete_elem(&tracked, &pid);
	return 0;
}

/* ===========================================================================
 * 1. process execution
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_EXEC, AM_F_EXEC);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[0]);
	am_capture_argv(e, (const char *const *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int on_execveat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_EXEC, AM_F_EXEC);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[1]);
	am_capture_argv(e, (const char *const *)ctx->args[2]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ===========================================================================
 * 2. file open — raw syscall arguments (default capture point)
 *
 * Paths are exactly what the program passed, so relative paths stay relative.
 * That is a feature for the measurement (it is how we quantify "260k
 * basename-only events") and the reason AM_DPATH=1 exists.
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_OPEN, AM_F_FILE);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[2];            /* flags */
	am_upath(e, (const void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int on_openat2(struct trace_event_raw_sys_enter *ctx)
{
	/* struct open_how's first member is `__u64 flags` (stable uapi). Read it
	 * by offset rather than by type: `struct open_how` is only present in
	 * vmlinux.h if the kernel's BTF happens to carry it, and a missing type
	 * would be a build failure for no gain. */
	__u64 how_flags = 0;
	struct event *e = am_ev(EV_OPEN, AM_F_FILE);
	if (!e)
		return 0;
	bpf_probe_read_user(&how_flags, sizeof(how_flags), (const void *)ctx->args[2]);
	e->arg1 = (int)how_flags;
	am_upath(e, (const void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#if AM_LEGACY_SYSCALLS
/* x86_64 only. glibc's open() for a non-AT call, and anything built against
 * an old libc, lands here — not on openat. */
SEC("tp/syscalls/sys_enter_open")
int on_open(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_OPEN, AM_F_FILE);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[1];            /* flags */
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_creat")
int on_creat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_OPEN, AM_F_FILE);
	if (!e)
		return 0;
	/* creat(path, mode) == open(path, O_WRONLY|O_CREAT|O_TRUNC, mode).
	 * Synthesise the flags so userspace's open_is_write() sees a write. */
	e->arg1 = AM_O_WRONLY | AM_O_CREAT | AM_O_TRUNC;
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
#endif /* AM_LEGACY_SYSCALLS */

/* ===========================================================================
 * 2b. file open — resolved path via LSM hook + bpf_d_path (AM_DPATH=1)
 *
 * security_file_open is on the kernel's bpf_d_path allow-list, so this is the
 * cheapest place to get an ABSOLUTE path. Trade-offs, both real:
 *   + every open, whatever syscall variant, through ONE hook (no x86/arm gap)
 *   + path is fully resolved (mounts, cwd, symlinks, chroot)
 *   - unstable ABI (a kernel function, not a tracepoint)
 *   - fires only on opens that reach the LSM, so FAILED opens disappear
 *     (ENOENT probes are exactly what a path-search looks like)
 * Selected at load time by Agentmo.c via bpf_program__set_autoload().
 * ========================================================================= */
SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	struct event *e = am_ev(EV_OPEN, AM_F_FILE);
	if (!e)
		return 0;
	e->arg1 = (int)BPF_CORE_READ(file, f_flags);
	e->eflags |= AM_EF_DPATH;
	bpf_d_path(&file->f_path, e->path, sizeof(e->path));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ===========================================================================
 * 3. delete
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_unlinkat")
int on_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_DEL, AM_F_FILE);
	if (!e)
		return 0;
	e->arg2 = (int)ctx->args[2];            /* AT_REMOVEDIR? */
	am_upath(e, (const void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#if AM_LEGACY_SYSCALLS
/* THE measured gap: python3's os.remove() issues unlink, not unlinkat. */
SEC("tp/syscalls/sys_enter_unlink")
int on_unlink(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_DEL, AM_F_FILE);
	if (!e)
		return 0;
	e->arg2 = 0;                            /* file, not dir */
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_rmdir")
int on_rmdir(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_DEL, AM_F_FILE);
	if (!e)
		return 0;
	e->arg2 = AT_REMOVEDIR;                 /* renders as op=rmdir */
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
#endif /* AM_LEGACY_SYSCALLS */

/* ===========================================================================
 * 4. rename
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_renameat2")
int on_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_REN, AM_F_FILE);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[1]);
	bpf_probe_read_user_str(&e->path2, sizeof(e->path2), (const char *)ctx->args[3]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int on_renameat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_REN, AM_F_FILE);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[1]);
	bpf_probe_read_user_str(&e->path2, sizeof(e->path2), (const char *)ctx->args[3]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#if AM_LEGACY_SYSCALLS
SEC("tp/syscalls/sys_enter_rename")
int on_rename(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_REN, AM_F_FILE);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[0]);
	bpf_probe_read_user_str(&e->path2, sizeof(e->path2), (const char *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
#endif /* AM_LEGACY_SYSCALLS */

/* ===========================================================================
 * 5. mkdir  (EV_MKDIR — added to Agentmo.h in v2)
 *
 * Kept as its own type rather than folded into EV_OPEN: "created a directory
 * here" is a distinct claim about the filesystem footprint, and mkpolicy.py
 * maps it to the same `write` prefix table so it still whitelists normally.
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_mkdirat")
int on_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_MKDIR, AM_F_FILE);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[2];            /* mode */
	am_upath(e, (const void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#if AM_LEGACY_SYSCALLS
SEC("tp/syscalls/sys_enter_mkdir")
int on_mkdir(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_MKDIR, AM_F_FILE);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[1];            /* mode */
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
#endif /* AM_LEGACY_SYSCALLS */

/* ===========================================================================
 * 6. permission / ownership
 *
 * AM_EF_PERM_OWN distinguishes chown (arg1=uid, arg2=gid) from chmod
 * (arg1=mode); without it the userspace printer cannot tell them apart.
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_fchmodat")
int on_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PERM, AM_F_PERM);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[2];            /* mode */
	am_upath(e, (const void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_fchownat")
int on_fchownat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PERM, AM_F_PERM);
	if (!e)
		return 0;
	e->eflags |= AM_EF_PERM_OWN;
	e->arg1 = (int)ctx->args[2];            /* uid */
	e->arg2 = (int)ctx->args[3];            /* gid */
	am_upath(e, (const void *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* fd-based: NO path is available. Emitted anyway — see header comment #5. */
SEC("tp/syscalls/sys_enter_fchmod")
int on_fchmod(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PERM, AM_F_PERM);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[1];            /* mode; path stays "" */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_fchown")
int on_fchown(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PERM, AM_F_PERM);
	if (!e)
		return 0;
	e->eflags |= AM_EF_PERM_OWN;
	e->arg1 = (int)ctx->args[1];            /* uid; path stays "" */
	e->arg2 = (int)ctx->args[2];            /* gid */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#if AM_LEGACY_SYSCALLS
SEC("tp/syscalls/sys_enter_chmod")
int on_chmod(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PERM, AM_F_PERM);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[1];            /* mode */
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_chown")
int on_chown(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PERM, AM_F_PERM);
	if (!e)
		return 0;
	e->eflags |= AM_EF_PERM_OWN;
	e->arg1 = (int)ctx->args[1];
	e->arg2 = (int)ctx->args[2];
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_lchown")
int on_lchown(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PERM, AM_F_PERM);
	if (!e)
		return 0;
	e->eflags |= AM_EF_PERM_OWN;
	e->arg1 = (int)ctx->args[1];
	e->arg2 = (int)ctx->args[2];
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
#endif /* AM_LEGACY_SYSCALLS */

/* ===========================================================================
 * 7. privilege escalation  (the whole setuid family, not just setuid)
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_setuid")
int on_setuid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PRIV, AM_F_PRIV);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[0];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setreuid")
int on_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PRIV, AM_F_PRIV);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[1];            /* euid */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setresuid")
int on_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PRIV, AM_F_PRIV);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[1];            /* euid */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setgid")
int on_setgid(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PRIV, AM_F_PRIV);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[0];
	e->arg2 = 1;                            /* marker: gid-side call */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ===========================================================================
 * 8. network
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr sa = {};
	struct sockaddr_in sin = {};
	struct event *e;

	if (!FEAT(AM_F_NET) || !am_scope())
		return 0;
	bpf_probe_read_user(&sa, sizeof(sa), (const void *)ctx->args[1]);
	if (sa.sa_family != AF_INET)
		return 0;
	bpf_probe_read_user(&sin, sizeof(sin), (const void *)ctx->args[1]);

	e = am_begin(EV_NET);
	if (!e)
		return 0;
	e->daddr = sin.sin_addr.s_addr;
	e->arg1  = bpf_ntohs(sin.sin_port);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ===========================================================================
 * 9. inter-process attack
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_kill")
int on_kill(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_KILL, AM_F_PROC);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[0];            /* target pid */
	e->arg2 = (int)ctx->args[1];            /* signal     */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int on_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_PTRACE, AM_F_PROC);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[0];            /* request    */
	e->arg2 = (int)ctx->args[1];            /* target pid */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ===========================================================================
 * 10. namespace / mount escape  (EV_NS — was an unfilled extension point)
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_mount")
int on_mount(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_NS, AM_F_KERNEL);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[1]);          /* target dir */
	bpf_probe_read_user_str(&e->path2, sizeof(e->path2), (const char *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_umount")
int on_umount(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_NS, AM_F_KERNEL);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_unshare")
int on_unshare(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_NS, AM_F_KERNEL);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[0];            /* clone flags */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setns")
int on_setns(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_NS, AM_F_KERNEL);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[1];            /* nstype */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_chroot")
int on_chroot(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_NS, AM_F_KERNEL);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ===========================================================================
 * 11. kernel / monitor tampering
 * ========================================================================= */
SEC("tp/syscalls/sys_enter_bpf")
int on_bpf(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_BPF, AM_F_KERNEL);
	if (!e)
		return 0;
	e->arg1 = (int)ctx->args[0];            /* bpf cmd */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_delete_module")
int on_delmod(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_MOD, AM_F_KERNEL);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_finit_module")
int on_finitmod(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_MOD, AM_F_KERNEL);
	if (!e)
		return 0;
	am_upath(e, (const void *)ctx->args[1]);          /* param string */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_init_module")
int on_initmod(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = am_ev(EV_MOD, AM_F_KERNEL);
	if (!e)
		return 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Extension point (deliberately unused this round): bpf_lsm hooks returning
 * -EPERM, gated on enforce_mode. BPF LSM is already enabled on all five nodes
 * (MDX_DEPLOY.md §3.1) so this needs no reboot when we get there. */
