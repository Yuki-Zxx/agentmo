/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 agentmo. */
/*
 * Agentmo.h — shared event schema and policy flags.
 *
 * Included by BOTH the kernel data plane (Agentmo.bpf.c) and the userspace
 * control plane (Agentmo.c). Keep it libc/libbpf-free so it stays includable
 * on both sides.
 *
 * ---------------------------------------------------------------------------
 * v2 CHANGES (field-sufficiency fix — "print out している情報は十分か")
 * ---------------------------------------------------------------------------
 * The v1 record already carried ts / arg1 / path2 across the kernel boundary,
 * but the userspace printf dropped them, so the logs could not answer:
 *   - WHEN did it happen?            (ts was never printed)
 *   - Was this open a READ or WRITE? (open flags were never printed)
 *   - Renamed TO what?               (path2 was never printed)
 *   - unlink or rmdir?               (AT_REMOVEDIR was never printed)
 *   - WHAT did the command do?       (argv was never even captured)
 * v2 adds the missing capture field (args[]) and the provenance/quality bits
 * that let the log report its own blind spots.
 * ---------------------------------------------------------------------------
 */
#ifndef __AGENTMO_H
#define __AGENTMO_H

#define TASK_COMM_LEN 16
#define MAX_PATH      256

/* argv capture budget, in bytes, per exec event (NUL-separated arg strings).
 *
 * COST NOTE: the ring buffer is 16 MB and records are FIXED size, so
 *   in-flight records ~= 16MB / sizeof(struct event).
 *   AM_ARGS_MAX=0    -> ~590 B/record -> ~28k records in flight
 *   AM_ARGS_MAX=512  -> ~1.1 kB/record -> ~15k records in flight
 *   AM_ARGS_MAX=2048 -> ~2.6 kB/record -> ~6k  records in flight
 * 512 covers the overwhelming majority of real command lines (a full
 * `sed -i 's/…/…/' file.yml` is ~100 B). Anything longer is truncated and
 * flagged with AM_EF_ARGS_TRUNC — never silently dropped.
 */
#define AM_ARGS_MAX   512
#define AM_ARGS_NMAX  32      /* max argv entries the kernel will walk */

/* Policy feature bits — userspace sets `policy_features` (const volatile) so a
 * single kernel object can turn categories on/off without a recompile. */
#define AM_F_EXEC     (1U << 0)
#define AM_F_FILE     (1U << 1)   /* open / delete / rename */
#define AM_F_PERM     (1U << 2)   /* chmod / chown */
#define AM_F_PRIV     (1U << 3)   /* setuid family */
#define AM_F_NET      (1U << 4)   /* connect */
#define AM_F_PROC     (1U << 5)   /* kill / ptrace */
#define AM_F_KERNEL   (1U << 6)   /* module / bpf / namespace */
#define AM_F_ENFORCE  (1U << 31)  /* observe-only (0) vs block-on-alert (1) */

/* Per-event provenance / quality flags (event.eflags).
 * These are what let the monitor QUANTIFY ITS OWN BLIND SPOTS: at exit the
 * control plane reports how many events had no usable path, how many argv
 * captures were truncated, and how many paths were absolute vs basename-only. */
#define AM_EF_ARGS_TRUNC (1U << 0)  /* argv did not fit in args[] (or > NMAX)  */
#define AM_EF_DPATH      (1U << 1)  /* path came from bpf_d_path() = absolute  */
#define AM_EF_PERM_OWN   (1U << 2)  /* EV_PERM is a chown (a1=uid,a2=gid);
                                     * clear => chmod (a1=mode)                */

/* One-to-one with the monitoring taxonomy. */
enum event_type {
	EV_EXEC = 1,   /* process execution              */
	EV_FORK,       /* process tree                   */
	EV_OPEN,       /* file open (read/write)         */
	EV_DEL,        /* delete: unlinkat               */
	EV_REN,        /* rename: renameat*              */
	EV_PERM,       /* perm/owner: fchmodat/fchownat  */
	EV_PRIV,       /* privilege: setuid family       */
	EV_NET,        /* connect                        */
	EV_KILL,       /* kill                           */
	EV_PTRACE,     /* ptrace                         */
	EV_NS,         /* mount/unshare/setns            */
	EV_MOD,        /* kernel module                  */
	EV_BPF,        /* bpf()                          */
	EV_MKDIR,      /* mkdir/mkdirat  (v2, appended)  */
	EV__MAX
};

/* Verdict computed by the policy engine (kernel in enforce mode, else user). */
enum verdict {
	V_SAFE  = 0,
	V_WATCH = 1,
	V_ALERT = 2,
};

/* Fixed-size record shipped over the ring buffer. Generic slots are reused
 * across event types; see the per-type field map in the control plane. */
struct event {
	unsigned long long ts;              /* bpf_ktime_get_ns (CLOCK_MONOTONIC)   */
	unsigned int  type;                 /* enum event_type                      */
	unsigned int  pid;                  /* subject pid (parent for FORK)        */
	unsigned int  ppid;                 /* real parent pid (CO-RE)              */
	unsigned int  uid;                  /* 1000 or 0                            */
	int           arg1;                 /* flags/mode/uid/port/child_pid/cmd    */
	int           arg2;                 /* at_flag / gid / signal               */
	unsigned int  daddr;                /* NET: dest IPv4 (network order)       */
	unsigned int  verdict;              /* enum verdict (kernel prelim)         */
	unsigned int  blocked;              /* 1 if an enforce hook denied the op   */
	unsigned int  killed;               /* 1 if the rule sent SIGKILL           */
	unsigned int  eflags;               /* NEW: AM_EF_* provenance/quality bits */
	unsigned int  argslen;              /* NEW: bytes used in args[]            */
	unsigned int  argsnum;              /* NEW: argv entries packed in args[]   */
	char comm[TASK_COMM_LEN];           /* subject process name                 */
	char path[MAX_PATH];                /* primary path / exe / dest / old name */
	char path2[MAX_PATH];               /* secondary path (rename new name)     */
	char args[AM_ARGS_MAX];             /* NEW: EXEC argv, NUL-separated        */
};

#endif /* __AGENTMO_H */
