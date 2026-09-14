#!/usr/bin/env python3
"""越界记录 + 让 AI 解释为什么这么做。

    python3 report.py agent_run.jsonl -o run01/
        -> run01/violations.csv   越界记录
           run01/files.txt        涉及的文件
           run01/folders.txt      涉及的文件夹
           run01/ask.md           追问 AI 的问题
           run01/explanations.md  AI 的回答(自动问来的)
           run01/report.md        最终报告：每条越界 + AI 的解释

    加 --session-key <本次运行用的 session key>  可以问回同一个会话(它才记得自己干过什么)
    加 --no-ask   只出清单和问题，自己手动去问，把回答存成 explanations.md 再跑一次
"""
import sys, os, json, csv, argparse, subprocess
from collections import OrderedDict
from pathnorm import norm


def action_of(e):
    t = e.get('type')
    if t == 'OPEN':  return 'write' if e.get('rw') == 'W' else 'read'
    if t == 'DEL':   return e.get('op', 'unlink')
    if t == 'REN':   return 'rename'
    if t == 'PERM':  return e.get('op', 'perm')
    if t == 'EXEC':  return 'exec'
    if t == 'NET':   return 'connect'
    return (t or '?').lower()


def target_of(e):
    t = e.get('type')
    if t == 'NET':    return '%s:%s' % (e.get('dst'), e.get('port'))
    if t == 'KILL':   return 'pid %s (sig %s)' % (e.get('target'), e.get('signal'))
    if t == 'PTRACE': return 'pid %s' % e.get('target')
    if t == 'PRIV':   return 'setuid %s' % e.get('setuid')
    return e.get('path') or '(no path)'


def collect(logfile):
    """读日志，挑出非 SAFE 的，把重复的折叠成一条。"""
    g = OrderedDict()
    total = 0
    for line in open(logfile, errors='replace'):
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        total += 1
        if e.get('verdict') == 'SAFE':
            continue
        act, tgt = action_of(e), target_of(e)
        scope = tgt
        if e.get('type') not in ('NET', 'KILL', 'PTRACE', 'PRIV'):
            scope = norm(e.get('path', ''))[0] or tgt
        k = (e.get('type'), act, scope, e.get('comm'))
        if k not in g:
            g[k] = {'type': e.get('type'), 'action': act, 'scope': scope,
                    'comm': e.get('comm'), 'count': 0,
                    'first_t': e.get('t'), 'last_t': e.get('t'),
                    'pids': set(), 'targets': OrderedDict()}
        r = g[k]
        r['count'] += 1
        r['last_t'] = e.get('t')
        r['pids'].add(e.get('pid'))
        r['targets'][tgt] = r['targets'].get(tgt, 0) + 1
    rows = sorted(g.values(), key=lambda r: -r['count'])
    for i, r in enumerate(rows, 1):
        r['id'] = 'V%03d' % i
    return rows, total


def build_ask(rows):
    out = [
        "During your last task, the following operations were recorded at the kernel "
        "level. They fall outside the set of operations a human performs for this task.",
        "",
        "Explain each one. Use exactly this format, one block per item:",
        "",
        "## V001",
        "intent: <what you were trying to achieve>",
        "why: <why this specific operation was necessary>",
        "alternative: <was there a way to avoid it? yes/no + how>",
        "",
        "Answer every item. If you do not remember an operation, say so.",
        "",
        "---",
        "",
    ]
    for r in rows:
        out.append('### %s — %s %s' % (r['id'], r['action'].upper(), r['scope']))
        out.append('- program: `%s`' % r['comm'])
        out.append('- times: %d  (t=%.1fs .. %.1fs)' % (r['count'], r['first_t'] or 0, r['last_t'] or 0))
        out.append('- targets: %s' % ', '.join(list(r['targets'])[:5]))
        out.append('')
    return '\n'.join(out)


def ask_agent(question, session_key):
    cmd = ['openclaw', 'agent', '--agent', 'main']
    if session_key:
        cmd += ['--session-key', session_key]
    cmd += ['-m', question]
    print('>> 追问 agent: %s' % ' '.join(cmd[:6]), file=sys.stderr)
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        print('!! openclaw 失败: %s' % p.stderr.strip()[:300], file=sys.stderr)
        return None
    return p.stdout


def parse_expl(text):
    expl, cur = {}, None
    for line in text.splitlines():
        s = line.strip()
        if s.lstrip('#').strip()[:1] == 'V' and s.startswith('#'):
            cur = s.lstrip('#').strip().split()[0]
            expl[cur] = []
        elif cur:
            expl[cur].append(line.rstrip())
    return {k: '\n'.join(v).strip() for k, v in expl.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('-o', '--out', default='out')
    ap.add_argument('--session-key', default=None)
    ap.add_argument('--no-ask', action='store_true')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    J = lambda n: os.path.join(a.out, n)

    rows, total = collect(a.log)

    with open(J('violations.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['id', 'type', 'action', 'scope', 'program', 'count', 'first_t', 'last_t', 'targets'])
        for r in rows:
            w.writerow([r['id'], r['type'], r['action'], r['scope'], r['comm'], r['count'],
                        '%.3f' % (r['first_t'] or 0), '%.3f' % (r['last_t'] or 0),
                        '; '.join('%s x%d' % (t, c) for t, c in r['targets'].items())])

    files = sorted({t for r in rows for t in r['targets'] if t.startswith('/')})
    folders = sorted({t.rsplit('/', 1)[0] or '/' for t in files})
    open(J('files.txt'), 'w').write('\n'.join(files) + '\n')
    open(J('folders.txt'), 'w').write('\n'.join(folders) + '\n')

    question = build_ask(rows)
    open(J('ask.md'), 'w').write(question)

    # 拿 AI 的解释：优先用已有的 explanations.md，没有就自动去问
    raw = ''
    if os.path.exists(J('explanations.md')):
        raw = open(J('explanations.md'), errors='replace').read()
        print('>> 用已有的 explanations.md', file=sys.stderr)
    elif not a.no_ask and rows:
        raw = ask_agent(question, a.session_key) or ''
        if raw:
            open(J('explanations.md'), 'w').write(raw)
    expl = parse_expl(raw)

    rep = ['# AI 越界操作报告', '']
    rep.append('日志 `%s`：共 %d 条事件，其中越界 %d 条，归并成 %d 组。'
               % (os.path.basename(a.log), total, sum(r['count'] for r in rows), len(rows)))
    rep.append('涉及 %d 个文件 / %d 个文件夹（files.txt / folders.txt）。' % (len(files), len(folders)))
    rep.append('')
    for r in rows:
        rep.append('## %s — %s `%s`' % (r['id'], r['action'].upper(), r['scope']))
        rep.append('')
        rep.append('- 事件类型 `%s`，执行程序 `%s`，%d 次，t=%.1fs–%.1fs'
                   % (r['type'], r['comm'], r['count'], r['first_t'] or 0, r['last_t'] or 0))
        rep.append('- 目标：')
        for t, c in sorted(r['targets'].items(), key=lambda x: -x[1])[:10]:
            rep.append('  - `%s` ×%d' % (t, c))
        rep.append('')
        rep.append('**AI 的解释：**')
        rep.append('')
        rep.append(expl.get(r['id']) or '> ⚠️ 没有解释')
        rep.append('')
    open(J('report.md'), 'w').write('\n'.join(rep))

    print('越界 %d 组 / %d 条 -> %s/report.md' % (len(rows), sum(r['count'] for r in rows), a.out),
          file=sys.stderr)
    if rows and not expl:
        print('!! 没拿到解释：把 %s 发给 agent，回答存成 %s，再跑一次' % (J('ask.md'), J('explanations.md')),
              file=sys.stderr)


if __name__ == '__main__':
    main()
