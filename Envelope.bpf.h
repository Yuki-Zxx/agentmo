/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2026 agentmon. */
/*
 * envelope.bpf.h — kernel-side "safe envelope" predicates and event emit.
 *
 * This is the kernel engine header (mirrors ActPlane's taint_engine.bpf.h):
 * it owns the ring buffer, the emit helper, and the always-inline predicates
 * a hook program calls. Requires vmlinux.h + bpf_helpers.h + "agentmon.h"
 * already included by the .bpf.c.
 *
 * Design note: observe mode emits every traced event and lets the userspace
 * control plane compute the final verdict (robust, easy to iterate). Enforce
 * mode uses the always-violation predicate below to set a preliminary verdict
 * in-kernel; the LSM deny path is a documented extension point.
 */
#ifndef __ENVELOPE_BPF_H
#define __ENVELOPE_BPF_H

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);   /* 16 MB */
} rb SEC(".maps");

/* uid filter: agent normally runs as 1000; 0 means it escalated. */
static __always_inline int am_traced(void)
{
	__u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
	return uid == 1000 || uid == 0;
}

/* Event types that are never expected from a well-behaved submission and thus
 * are violations on sight (used by the enforce path; userspace refines the
 * path/net-dependent ones). */
static __always_inline int am_always_violation(__u32 type)
{
	switch (type) {
	case EV_PRIV:
	case EV_PTRACE:
	case EV_NS:
	case EV_MOD:
	case EV_BPF:
		return 1;
	default:
		return 0;
	}
}

/* Reserve + pre-fill the common header. Returns NULL on ring-buffer full.
 *
 * v2 NOTE — why there is no __builtin_memset() here any more:
 * sizeof(struct event) grew past 1 kB when args[512] was added for argv
 * capture. clang's BPF backend can only expand a memset inline up to a small
 * size; beyond that it emits a libcall, which BPF has no linker for, and the
 * build dies with "A call to built-in function 'memset' is not supported".
 * (The 8/25 record was ~590 B and squeaked under the limit, which is why this
 * only breaks now.)
 *
 * So: every scalar is assigned explicitly, and the three string buffers are
 * terminated at byte 0. Nothing downstream ever reads past a NUL — the
 * userspace printer escapes C strings and argv is walked using argslen /
 * argsnum — so the uninitialised tail of the ring-buffer slot is never
 * rendered. The useful side effect: a capture helper that FAILS leaves the
 * buffer as an empty string rather than stale garbage, so the failure shows up
 * honestly as "missing path" in the field-sufficiency self-report.
 */
static __always_inline struct event *am_begin(__u32 type)
{
	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->ts      = bpf_ktime_get_ns();
	e->type    = type;
	e->pid     = bpf_get_current_pid_tgid() >> 32;
	e->uid     = bpf_get_current_uid_gid() & 0xffffffff;
	e->ppid    = BPF_CORE_READ(t, real_parent, tgid);
	e->arg1    = 0;
	e->arg2    = 0;
	e->daddr   = 0;
	e->verdict = am_always_violation(type) ? V_ALERT : V_SAFE;
	e->blocked = 0;
	e->killed  = 0;
	e->eflags  = 0;
	e->argslen = 0;
	e->argsnum = 0;
	e->path[0]  = '\0';
	e->path2[0] = '\0';
	e->args[0]  = '\0';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

#endif /* __ENVELOPE_BPF_H */