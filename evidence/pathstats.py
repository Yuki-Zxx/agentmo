#!/usr/bin/env python3
"""Agentmo 日志的路径质量分析。

监控自己说得出自己的盲区，这份数字就是那句话的证据。Agentmo 退出时打的
FIELD SUFFICIENCY SELF-REPORT 只给总数；这里拆到「是谁产生的」「具体是哪些路径」，
因为白名单能不能建起来，取决于不可解析的那部分集中在少数几个程序上（可以定点处理），
还是均匀摊在所有程序上（那就只能换 hook 层）。

用法:
    # 单份日志的拆解
    python3 pathstats.py smoke/raw/agentmo_smoke.jsonl

    # 两个捕获点的对照（raw vs d_path）
    python3 pathstats.py --compare smoke/raw/agentmo_smoke.jsonl \\
                                   smoke/dpath/agentmo_smoke.jsonl
"""
import sys, json, argparse
from collections import Counter, defaultdict

PATH_TYPES = ('OPEN', 'DEL', 'REN', 'PERM', 'EXEC', 'MKDIR')


def load(path):
    ev = []
    with open(path, errors='replace') as f:
        for line in f:
            line = line.strip()
            if line.startswith('{'):
                try:
                    ev.append(json.loads(line))
                except Exception:
                    pass
    return ev


def quality(ev):
    """(abs, rel, none, total) over path-bearing events."""
    k = Counter(e.get('path_kind') for e in ev if e.get('type') in PATH_TYPES)
    return k.get('abs', 0), k.get('rel', 0), k.get('none', 0), sum(k.values())


def pct(n, d):
    return (100.0 * n / d) if d else 0.0


def report_one(path, ev):
    a, r, n, tot = quality(ev)
    print("=" * 72)
    print("%s   events=%d" % (path, len(ev)))
    print("=" * 72)
    print("按类型: %s" % dict(Counter(e.get('type') for e in ev)))
    srcs = Counter(e.get('src') for e in ev if e.get('type') == 'OPEN')
    if srcs:
        print("OPEN 捕获点: %s" % dict(srcs))
    if not tot:
        print("没有带路径的事件。")
        return

    print("\n路径质量（带路径的 %d 条）" % tot)
    print("  absolute %6d  %5.1f%%   可解析到具体文件 -> 能进白名单" % (a, pct(a, tot)))
    print("  relative %6d  %5.1f%%   只有相对路径/basename -> 进不了白名单" % (r, pct(r, tot)))
    print("  missing  %6d  %5.1f%%   连路径都没有（fd 型调用）" % (n, pct(n, tot)))

    # 不可解析的都是谁产生的
    by_comm = defaultdict(Counter)
    for e in ev:
        if e.get('type') in PATH_TYPES:
            by_comm[e.get('comm')][e.get('path_kind')] += 1
    rows = sorted(by_comm.items(),
                  key=lambda kv: -(kv[1].get('rel', 0) + kv[1].get('none', 0)))
    print("\n不可解析事件的来源程序（rel+none 降序，前 12）")
    print("  %-18s %8s %8s %8s   %s" % ("comm", "abs", "rel", "none", "不可解析占比"))
    for comm, k in rows[:12]:
        t = sum(k.values())
        u = k.get('rel', 0) + k.get('none', 0)
        print("  %-18s %8d %8d %8d   %5.1f%%"
              % (comm, k.get('abs', 0), k.get('rel', 0), k.get('none', 0), pct(u, t)))

    # 具体是哪些相对路径
    relp = Counter(e.get('path') for e in ev
                   if e.get('type') in PATH_TYPES and e.get('path_kind') == 'rel')
    if relp:
        print("\n出现最多的相对路径（前 15）—— 看它们集中不集中")
        for p, c in relp.most_common(15):
            print("  %6d  %s" % (c, p))
        print("  相对路径去重后共 %d 种" % len(relp))

    ex = [e for e in ev if e.get('type') == 'EXEC']
    if ex:
        noargv = sum(1 for e in ex if not e.get('argc'))
        trunc = sum(1 for e in ex if e.get('argv_trunc'))
        relex = sum(1 for e in ex if e.get('path_kind') != 'abs')
        print("\nEXEC: %d 条，无 argv %d 条，argv 被截断 %d 条，路径非绝对 %d 条"
              % (len(ex), noargv, trunc, relex))
        if relex:
            print("  ↑ 非绝对路径的 exec 永远匹配不上完整路径白名单，会一直判越界。"
                  "\n    这不是 bug，是「捕获点给不出对象身份」的直接后果，报告里要单列。")


def report_compare(pa, pb):
    ea, eb = load(pa), load(pb)
    aa, ra, na, ta = quality(ea)
    ab, rb, nb, tb = quality(eb)
    oa = sum(1 for e in ea if e.get('type') == 'OPEN')
    ob = sum(1 for e in eb if e.get('type') == 'OPEN')

    print("=" * 72)
    print("捕获点对照：原始 syscall 参数  vs  security_file_open + bpf_d_path")
    print("=" * 72)
    print("  A = %s" % pa)
    print("  B = %s" % pb)
    print()
    print("  %-28s %12s %12s %12s" % ("", "A (raw)", "B (d_path)", "差"))
    def row(label, x, y, p=False):
        d = y - x
        if p:
            print("  %-28s %11.1f%% %11.1f%% %+11.1f" % (label, x, y, d))
        else:
            print("  %-28s %12d %12d %+12d" % (label, x, y, d))
    row("事件总数", len(ea), len(eb))
    row("OPEN 事件数", oa, ob)
    row("带路径事件数", ta, tb)
    row("absolute 占比", pct(aa, ta), pct(ab, tb), p=True)
    row("relative 占比", pct(ra, ta), pct(rb, tb), p=True)

    print("""
怎么读这张表:
  * absolute 占比上升 = d_path 把路径解析成了真实对象，白名单才有东西可匹配。
  * OPEN/事件总数下降 = 代价。security_file_open 只在打开成功时触发，
    失败的 open 整批消失 —— 而失败的 open 正是「路径探测 / PATH 试探」的样子，
    也就是绕过行为最先露头的地方。
  * 所以两个都不够：raw 看得全但认不出对象，d_path 认得出对象但看不见失败。
    这条就是论文里「hook 到哪一层」那一节的实测依据。""")
    if ob and oa and ob < oa:
        print("  本次 d_path 少看到 %d 次 open（%.1f%%）。"
              % (oa - ob, pct(oa - ob, oa)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('logs', nargs='+')
    ap.add_argument('--compare', action='store_true',
                    help='两份日志对照（第一份 raw，第二份 d_path）')
    a = ap.parse_args()
    if a.compare:
        if len(a.logs) != 2:
            ap.error('--compare 需要正好两份日志')
        report_compare(a.logs[0], a.logs[1])
    else:
        for p in a.logs:
            report_one(p, load(p))
            print()


if __name__ == '__main__':
    main()
