#!/usr/bin/env python3
"""路径归一化 —— 把每次运行都会变的目录段折叠掉。

不做这一步，白名单里存的是 run0001/ tmpab12cd/ 12345/ 这种一次性路径，
下一次运行永远不命中，全部变成假阳性。
"""
import re

# 一个路径段长这样 = 每次运行都会变
VOLATILE = [
    re.compile(r'^run\d+$'),                     # pegasus run0001
    re.compile(r'^tmp[A-Za-z0-9_.\-]{5,}$'),     # python 临时目录
    re.compile(r'^\d{4,}$'),                     # pid / 纯数字
    re.compile(r'^[0-9a-fA-F]{8,}$'),            # hash / uuid 片段
    re.compile(r'\d{6,}'),                       # 内嵌长数字(时间戳)
    re.compile(r'^\d{4}-?\d{2}-?\d{2}[T_\-]'),   # 日期时间目录
]

SYS_ROOTS = ('usr', 'lib', 'lib64', 'proc', 'sys', 'dev', 'etc', 'snap', 'var', 'opt', 'bin', 'sbin')
SYS_DEPTH = 2      # /usr/lib/... -> /usr/lib/
USR_DEPTH = 3      # /home/ubuntu/.pegasus/... -> /home/ubuntu/.pegasus/


def is_volatile(seg):
    return any(p.search(seg) for p in VOLATILE)


def norm(path, sys_depth=SYS_DEPTH, usr_depth=USR_DEPTH):
    """返回 (rule, kind)。rule 以 '/' 结尾 = 目录前缀；否则 = 精确文件。
    path 不是绝对路径时返回 (None, 'rel')。"""
    if not path:
        return None, 'none'
    if not path.startswith('/'):
        return None, 'rel'

    segs = [s for s in path.split('/') if s]
    if not segs:
        return '/', 'dir'

    depth = sys_depth if segs[0] in SYS_ROOTS else usr_depth

    kept = []
    truncated = False
    for i, s in enumerate(segs):
        if is_volatile(s):
            truncated = True
            break
        if len(kept) >= depth:
            truncated = True
            break
        kept.append(s)

    if not kept:
        return '/', 'dir'
    # 整条路径都被保留 = 这是个短路径，当精确文件用
    if not truncated and len(kept) == len(segs):
        return '/' + '/'.join(kept), 'file'
    return '/' + '/'.join(kept) + '/', 'dir'


def dedup_prefixes(rules):
    """/a/b/ 已经在里面，就不必再留 /a/b/c/ 或 /a/b/x"""
    dirs = sorted([r for r in rules if r.endswith('/')], key=len)
    keep_dirs = []
    for d in dirs:
        if not any(d != k and d.startswith(k) for k in keep_dirs):
            keep_dirs.append(d)
    out = list(keep_dirs)
    for r in rules:
        if r.endswith('/'):
            continue
        if not any(r.startswith(k) for k in keep_dirs):
            out.append(r)
    return sorted(set(out))
