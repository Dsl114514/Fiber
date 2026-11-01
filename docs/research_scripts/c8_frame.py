#!/usr/bin/env python3
"""c8_frame.py - Identify 0x7C65DA0 / 0x7C668D0 (callers of update candidates)
via strings + their callers; also strings inside candidates."""
import sys, struct
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
    if len(s) >= 4 and all(32 <= ord(c) < 127 or c in '\n\r\t' for c in s):
        return s
    return None

def func_strings(fstart, fend, cap=28, minlen=6):
    lo_off = fstart - T_RVA + T_OFF
    n = fend - fstart
    if n <= 4: return {}
    cnt = n - 3
    disps = np.frombuffer(d, dtype=np.int32, count=cnt, offset=lo_off)
    p = np.arange(fstart, fstart + cnt, dtype=np.int64)
    t = p + 4 + disps
    m = (t >= rd['vaddr']) & (t < rd['vaddr'] + rd['vsize'])
    strs = {}
    for k in np.flatnonzero(m):
        s = cstring_at(int(t[k]))
        if s and len(s) >= minlen:
            strs[s] = int(p[k])
    # prefer distinctive: sort by rarity-ish (contains :: or / or spaces)
    def score(s):
        return ('::' in s) + ('/' in s) + (' ' in s) + (len(s) > 20)
    items = sorted(strs.items(), key=lambda kv: -score(kv[0]))
    return dict(items[:cap])

def callers(lo, hi):
    m = (T >= lo) & (T < hi)
    out = {}
    for s in S[m]:
        f = pd.floor(int(s))
        if f: out.setdefault(f[0], []).append(int(s))
    return out

for fn in (0x7C65DA0, 0x7C668D0, 0x87AB10, 0x87AC90, 0xB038580, 0x287B510, 0x25F2D30):
    f = pd.find(fn)
    print(f"\n{'='*76}\nFUNC 0x{fn:X} (0x{f[0]:X}-0x{f[1]:X} sz 0x{f[1]-f[0]:X})")
    st = func_strings(f[0], f[1])
    for s, site in st.items():
        print(f"   str@0x{site:X}: {s[:100]}")
    cl = callers(f[0], f[1])
    ext = {b: sites for b, sites in cl.items() if b != f[0]}
    print(f"  external callers: {len(ext)}")
    for b, sites in sorted(ext.items(), key=lambda kv: -len(kv[1]))[:10]:
        fe = pd.find(b)
        print(f"    caller 0x{b:X}-0x{fe[1]:X} (sz 0x{fe[1]-b:X}) sites={[hex(x) for x in sites[:6]]}")
