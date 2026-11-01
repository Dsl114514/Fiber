#!/usr/bin/env python3
"""c9_tree.py - Print the full caller tree of 0x87AC90 (depth 3, with string IDs).
Also check which callers are unique (recursion) vs real."""
import sys
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
S = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_S.npy')
T = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_T.npy')
T_OFF = pe.sec_by_name('.text')['raddr']
T_RVA = pe.sec_by_name('.text')['vaddr']
rd = pe.sec_by_name('.rdata')

def cstring_at(rva, maxlen=110):
    off = pe.rva2off(rva)
    if off < 0: return None
    end = d.find(b'\x00', off, off + maxlen)
    if end <= off: return None
    b = d[off:end]
    try: s = b.decode('utf-8')
    except UnicodeDecodeError: return None
    if len(s) >= 4 and all(32 <= ord(c) < 127 for c in s):
        return s
    return None

def func_strings(fstart, fend, cap=8, minlen=10):
    lo_off = fstart - T_RVA + T_OFF
    n = fend - fstart
    if n <= 4: return []
    cnt = n - 3
    disps = np.frombuffer(d, dtype=np.int32, count=cnt, offset=lo_off)
    p = np.arange(fstart, fstart + cnt, dtype=np.int64)
    t = p + 4 + disps
    m = (t >= rd['vaddr']) & (t < rd['vaddr'] + rd['vsize'])
    out = []
    for k in np.flatnonzero(m):
        s = cstring_at(int(t[k]))
        if s and len(s) >= minlen:
            out.append(s)
    seen = set(); res = []
    for s in out:
        if s not in seen:
            seen.add(s); res.append(s)
        if len(res) >= cap: break
    return res

def callers(lo, hi):
    m = (T >= lo) & (T < hi)
    out = {}
    for s in S[m]:
        f = pd.floor(int(s))
        if f: out.setdefault(f[0], []).append(int(s))
    return out

ROOT = 0x87AC90

def walk(fn, depth, maxdepth, path):
    f = pd.find(fn)
    st = func_strings(f[0], f[1], cap=5)
    tag = ' | '.join(s[-60:] for s in st[:3])
    print(f"{'  '*depth}0x{fn:X} (sz 0x{f[1]-f[0]:X}) {tag}")
    if depth >= maxdepth: return
    cl = callers(f[0], f[1])
    ext = sorted(b for b in cl if b != f[0])
    for b in ext[:8]:
        walk(b, depth + 1, maxdepth, path + [b])

print("CALLER TREE of MinecraftGame::update candidate 0x87AC90:")
walk(ROOT, 0, 3, [])
