#!/usr/bin/env python3
"""人工基线运行的 Agentmo 日志  ->  policy.conf 白名单

用法:
    # 人工跑 workflow 时，全量抓（注意 AM_ALL=1，SAFE 也要）
    AM_ALL=1 AM_JSON=1 sudo ./Agentmo $$ policy_empty.conf > human1.jsonl
    # 跑 N 次，然后取并集
    python3 mkpolicy.py human1.jsonl human2.jsonl human3.jsonl -o policy.conf
"""
import sys, json, argparse
from collections import Counter, defaultdict
from pathnorm import norm, dedup_prefixes

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('logs', nargs='+', help='Agentmo JSONL 日志(人工基线运行)')
    ap.add_argument('-o', '--out', default='policy.conf')
    ap.add_argument('--min-runs', type=int, default=1,
                    help='一条规则至少要在几份日志里出现过才收(默认1)')
    args = ap.parse_args()

    # rule -> {kind: {log: count}}
    support = defaultdict(lambda: defaultdict(Counter))
    sample  = {}
    stats   = Counter()

    for log in args.logs:
        with open(log, errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('{'):
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    stats['badjson'] += 1
                    continue
                stats['events'] += 1
                t, p = e.get('type'), e.get('path', '')

                if t == 'EXEC':
                    # 完整路径，不是 basename。basename 级白名单 = PATH 劫持盲区
                    # （exec node 会连 /tmp/node 一起放行），见 MDX_DEPLOY.md 5.1。
                    # Agentmo.c 的 exec_ok() 也按完整路径匹配，两边必须一致。
                    if p.startswith('/'):
                        support[p]['exec'][log] += 1
                        sample.setdefault(('exec', p), p)
                    elif p:
                        stats['exec_relpath'] += 1   # 相对路径，无法进白名单
                    else:
                        stats['exec_nopath'] += 1
                    continue

                if t == 'NET':
                    dst = e.get('dst')
                    if dst and dst != '0.0.0.0':
                        r = dst + '/32'
                        support[r]['net'][log] += 1
                        sample.setdefault(('net', r), '%s:%s' % (dst, e.get('port')))
                    continue

                if t in ('OPEN', 'DEL', 'REN', 'PERM', 'MKDIR'):
                    rule, kind = norm(p)
                    if rule is None:
                        stats['path_' + kind] += 1
                        continue
                    # Agentmo 的 classify(): DEL/REN/PERM 都查 write 表
                    which = 'write' if (t != 'OPEN' or e.get('rw') == 'W') else 'read'
                    support[rule][which][log] += 1
                    sample.setdefault((which, rule), p)
                    if t == 'REN' and e.get('path2'):
                        r2, k2 = norm(e['path2'])
                        if r2:
                            support[r2]['write'][log] += 1
                    continue

                stats['skip_' + str(t)] += 1

    # 收敛成四类规则
    buckets = {'read': [], 'write': [], 'exec': [], 'net': []}
    counts  = {}
    for rule, kinds in support.items():
        for kind, per_log in kinds.items():
            if len(per_log) < args.min_runs:
                continue
            buckets[kind].append(rule)
            counts[(kind, rule)] = (sum(per_log.values()), len(per_log))

    for k in ('read', 'write'):
        buckets[k] = dedup_prefixes(buckets[k])
    buckets['exec'] = sorted(set(buckets['exec']))
    buckets['net']  = sorted(set(buckets['net']))
    # write 蕴含 read：写过的地方也允许读
    buckets['read'] = dedup_prefixes(buckets['read'] + buckets['write'])

    with open(args.out, 'w') as f:
        w = f.write
        w("# agentmo allow-list — 由人工基线运行自动生成 (DEFAULT-DENY)\n")
        w("# 生成自: %s\n" % ', '.join(args.logs))
        w("# 事件总数 %d | 相对路径 %d 条 | 无路径 %d 条 (这些没法进白名单，见 README)\n"
          % (stats['events'], stats['path_rel'], stats['path_none']))
        w("# 格式: read <前缀> | write <前缀> | exec <完整路径或 '/' 结尾的前缀> | net <cidr>\n")
        w("# 行尾 (n/m) = 命中 n 次 / 出现在 m 份人工日志里。只在 1 份里出现的建议人工复核。\n\n")
        for kind in ('read', 'write', 'exec', 'net'):
            w("# ---------------------------------------------------------- %s\n" % kind)
            for r in buckets[kind]:
                n, m = counts.get((kind, r)) or counts.get(('write', r)) or (0, 0)
                w("%-6s %-50s # (%d/%d)\n" % (kind, r, n, m))
            w("\n")

    print("写出 %s" % args.out, file=sys.stderr)
    for kind in ('read', 'write', 'exec', 'net'):
        print("  %-6s %d 条" % (kind, len(buckets[kind])), file=sys.stderr)
    print("  事件 %d | 相对路径 %d | 无路径 %d" %
          (stats['events'], stats['path_rel'], stats['path_none']), file=sys.stderr)

if __name__ == '__main__':
    main()
