#!/usr/bin/env bash
# ============================================================================
# Agentmo v2 smoke test — mdx / x86_64
#
#   ./smoketest.sh            # raw syscall args   (default capture point)
#   ./smoketest.sh dpath      # security_file_open + bpf_d_path
#   ./smoketest.sh both       # run both on an IDENTICAL probe set, then compare
#
# Answers four questions before we spend a real experiment run on it:
#   1. Does it build and attach at all?
#   2. Does it catch the x86_64 LEGACY syscall variants that v1 missed?
#      (MDX_DEPLOY.md 4 measured this for unlink; on glibc/x86_64 the same is
#       true for rename, chmod, chown, mkdir and rmdir — glibc issues the plain
#       syscall whenever __NR_<name> exists, which on x86_64 it does. So v1 was
#       blind to ALL of those, not only python's delete.)
#   3. Is the scope really the PID SUBTREE, not the machine?
#      (a process started by systemd — outside the anchor's tree — must produce
#       zero events, even though it runs as the same uid.)
#   4. How much does the capture POINT change the usable-path rate?
#      'both' runs the same probes twice and prints the abs/rel table. That
#      table is the answer to "which layer must you hook to get a usable path,
#      and what does it cost" — and the cost shows up as the event-count drop,
#      because security_file_open never fires for a FAILED open.
#
# Output: smoke/raw/  and/or  smoke/dpath/   (jsonl + stderr + PASS/FAIL table)
#
# Note: Agentmo is started as a child of this script, so the anchor's subtree
# contains Agentmo itself. Its own few events are expected and ignored.
# ============================================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-raw}"
BIN="$HERE/Agentmo"

[ -x "$BIN" ] || { echo "no $BIN — run 'make' first"; exit 1; }
# Grab a sudo ticket up front: the run below backgrounds sudo, and a password
# prompt from a background job does not reach the terminal cleanly.
sudo -v || exit 1

# ---------------------------------------------------------------- both mode
if [ "$MODE" = both ]; then
	"$0" raw   || true
	echo; echo "=============================================================="; echo
	"$0" dpath || true
	echo
	python3 "$HERE/evidence/pathstats.py" --compare \
		"$HERE/smoke/raw/agentmo_smoke.jsonl" \
		"$HERE/smoke/dpath/agentmo_smoke.jsonl"
	exit $?
fi

case "$MODE" in
	raw)   DPATH_ENV=""        ; LABEL="raw syscall args" ;;
	dpath) DPATH_ENV="AM_DPATH=1"; LABEL="security_file_open + bpf_d_path" ;;
	*) echo "usage: $0 [raw|dpath|both]"; exit 2 ;;
esac

OUT="$HERE/smoke/$MODE"
LOG="$OUT/agentmo_smoke.jsonl"
ERR="$OUT/agentmo_smoke.stderr"
WORK="$OUT/work"

rm -rf "$OUT"; mkdir -p "$WORK"
: > "$OUT/empty.conf"

echo ">> mode = $MODE ($LABEL)"
echo ">> anchor pid = $$"
# shellcheck disable=SC2086
env AM_ALL=1 AM_JSON=1 $DPATH_ENV sudo -E "$BIN" $$ "$OUT/empty.conf" > "$LOG" 2> "$ERR" &
AMPID=$!

# Wait for attach. Agentmo prints its banner to stderr once it is polling.
for _ in $(seq 1 50); do
	grep -q 'Agentmo running' "$ERR" 2>/dev/null && break
	sleep 0.2
done
grep -q 'Agentmo running' "$ERR" || { echo "FAILED TO START:"; cat "$ERR"; exit 1; }
sleep 0.5
echo ">> attached; running probes"

cd "$WORK" || exit 1

# ---- 1. coreutils / shell side -------------------------------------------
touch  cu_file
mkdir  cu_dir                                  # glibc mkdir()  -> SYS_mkdir
mv     cu_file cu_file2                        # coreutils      -> renameat2/rename
chmod  0700    cu_file2                        # glibc chmod()  -> SYS_chmod
rm     cu_file2                                # coreutils rm   -> unlinkat
rmdir  cu_dir                                  # glibc rmdir()  -> SYS_rmdir
sed -n '1p' /etc/hostname > /dev/null          # argv capture probe

# ---- 2. python side (the variant gap that was actually measured) ----------
python3 - <<'PY'
import os, socket
os.mkdir('py_dir')                 # SYS_mkdir
open('py_file', 'w').write('x')    # SYS_openat (write)
os.rename('py_file', 'py_file2')   # SYS_rename   <-- v1 hooked only renameat2
os.chmod('py_file2', 0o600)        # SYS_chmod    <-- v1 hooked only fchmodat
os.chown('py_file2', os.getuid(), os.getgid())   # SYS_chown
os.remove('py_file2')              # SYS_unlink   <-- the measured gap
os.rmdir('py_dir')                 # SYS_rmdir
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(('127.0.0.1', 9))    # SYS_connect -> EV_NET
except OSError:
    pass
s.close()
PY

# ---- 2b. a FAILED open, on purpose ---------------------------------------
# This is the one action the two capture points disagree about by design:
# the raw syscall hook sees it, security_file_open never fires. A path probe
# (PATH search, "does this config exist") looks exactly like this.
cat /nonexistent_am_probe_file 2>/dev/null

# ---- 3. scope test: something OUTSIDE the anchor subtree ------------------
OUTSIDE_OK=skip
if command -v systemd-run >/dev/null 2>&1; then
	if systemd-run --user --collect --quiet \
	     /usr/bin/touch "$WORK/OUTSIDE_MARKER" 2>/dev/null; then
		OUTSIDE_OK=yes
		sleep 1
	fi
fi

sleep 1
# Agentmo runs under sudo, so $AMPID is a ROOT-owned process: a plain
# `kill` from mdxuser gets EPERM and the script hangs in wait until someone
# presses Ctrl-C. Signal it as root.
sudo kill -INT "$AMPID" 2>/dev/null || kill -INT "$AMPID" 2>/dev/null
for _ in $(seq 1 30); do
	kill -0 "$AMPID" 2>/dev/null || break
	sleep 0.2
done
kill -0 "$AMPID" 2>/dev/null && sudo kill -TERM "$AMPID" 2>/dev/null
wait "$AMPID" 2>/dev/null
cd "$HERE" || exit 1

echo
python3 - "$LOG" "$OUTSIDE_OK" "$MODE" <<'PY'
import sys, json, collections

log, outside, mode = sys.argv[1], sys.argv[2], sys.argv[3]
ev, bad = [], 0
for line in open(log, errors='replace'):
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        ev.append(json.loads(line))
    except Exception:
        bad += 1

def any_ev(**kw):
    return next((e for e in ev if all(e.get(k) == v for k, v in kw.items())), None)

def path_ev(t, frag, **kw):
    for e in ev:
        if e.get('type') != t:
            continue
        if frag not in (e.get('path') or '') and frag not in (e.get('path2') or ''):
            continue
        if all(e.get(k) == v for k, v in kw.items()):
            return e
    return None

checks = [
    ("ring buffer produced events",         len(ev) > 0),
    ("no malformed JSON lines",             bad == 0),
    ("EXEC captured",                       any_ev(type='EXEC') is not None),
    ("EXEC argv captured (argc>1)",         any(e.get('type')=='EXEC' and e.get('argc',0)>1 for e in ev)),
    ("FORK captured (subtree registration)",any_ev(type='FORK') is not None),
    ("OPEN write captured",                 path_ev('OPEN','py_file', rw='W') is not None),
    ("MKDIR captured  [new in v2]",         path_ev('MKDIR','cu_dir') is not None
                                            or path_ev('MKDIR','py_dir') is not None),
    ("REN  coreutils mv",                   path_ev('REN','cu_file') is not None),
    ("REN  python os.rename [x86 variant]", path_ev('REN','py_file') is not None),
    ("PERM chmod coreutils",                path_ev('PERM','cu_file2', op='chmod') is not None),
    ("PERM chmod python    [x86 variant]",  path_ev('PERM','py_file2', op='chmod') is not None),
    ("PERM chown python    [x86 variant]",  path_ev('PERM','py_file2', op='chown') is not None),
    ("DEL  rm -> unlinkat",                 path_ev('DEL','cu_file2', op='unlink') is not None),
    ("DEL  python os.remove [THE gap]",     path_ev('DEL','py_file2', op='unlink') is not None),
    ("DEL  rmdir -> op=rmdir",              path_ev('DEL','cu_dir', op='rmdir') is not None
                                            or path_ev('DEL','py_dir', op='rmdir') is not None),
    ("NET  connect captured",               any_ev(type='NET') is not None),
]
if outside == 'yes':
    checks.append(("SCOPE: systemd-run child NOT traced",
                   not any('OUTSIDE_MARKER' in (e.get('path') or '') for e in ev)))

# The capture points are SUPPOSED to disagree here; assert the expected side.
failed_open = path_ev('OPEN', 'nonexistent_am_probe_file')
srcs = {e.get('src') for e in ev if e.get('type') == 'OPEN'}
if mode == 'raw':
    checks.append(("failed open IS seen (raw syscall arg)", failed_open is not None))
    checks.append(("OPEN src == syscall",                   srcs <= {'syscall'}))
else:
    checks.append(("failed open NOT seen (d_path, expected)", failed_open is None))
    checks.append(("OPEN src == d_path (no double-count)",    srcs <= {'d_path'}))

w = max(len(c[0]) for c in checks)
fail = sum(0 if ok else 1 for _, ok in checks)
for name, ok in checks:
    print("  %-*s  %s" % (w, name, "PASS" if ok else "FAIL"))
if outside != 'yes':
    print("  %-*s  SKIP (systemd-run unavailable)" % (w, "SCOPE: outside-subtree check"))

print("\n  events=%d  by type: %s" % (
    len(ev), dict(collections.Counter(e.get('type') for e in ev))))
paths = [e for e in ev if e.get('type') in ('OPEN','DEL','REN','PERM','EXEC','MKDIR')]
if paths:
    k = collections.Counter(e.get('path_kind') for e in paths)
    tot = sum(k.values())
    print("  path quality: abs=%d (%.1f%%)  rel=%d (%.1f%%)  none=%d"
          % (k.get('abs',0), 100.0*k.get('abs',0)/tot,
             k.get('rel',0), 100.0*k.get('rel',0)/tot, k.get('none',0)))
print("\n  %s" % ("ALL CHECKS PASSED" if fail == 0 else "%d CHECK(S) FAILED" % fail))
sys.exit(1 if fail else 0)
PY
rc=$?

echo
echo ">> raw log : $LOG"
echo ">> stderr  : $ERR   (attestation + field-sufficiency self-report)"
[ "$MODE" = raw ] && echo ">> next    : ./smoketest.sh both   # runs dpath too and prints the comparison"
exit $rc
