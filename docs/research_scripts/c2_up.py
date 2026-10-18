#!/usr/bin/env python3
"""c2_up.py - Walk up the caller chain from TextPacketPayload handler's callers,
identifying each function by the .rdata strings it rip-references.
"""
import sys, re
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
S = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_S.npy')
T = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_T.npy')

d = pe.data
T_OFF = pe.sec_by_name('.text')['raddr']
T_RVA = pe.sec_by_name('.text')['vaddr']

def cstring_at(rva, maxlen=120):
    off = pe.rva2off(rva)
    if off < 0:
        return None
    end = d.find(b'\x00', off, off + maxlen + 4)
    if end < 0:
        return None
    b = d[off:end]
    if len(b) == 0:
        return None
    try:
        s = b.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if len(s) < 3:
        return None
    if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in s):
        return s
    return None

def func_strings(fstart, fend):
    """All rip-relative refs from [fstart,fend) into .rdata that resolve to C strings."""
    lo, hi = fstart, fend
    m = (S >= lo) & (S < hi)
    if not m.any():
        return []
    idx = np.flatnonzero(m)
    # rip = site+4 (disp32 end); we need raw disps: recompute from data
    strs = {}
    for i in idx:
        site = int(S[i])
        off = site - T_RVA + T_OFF  # .text: rva->off subtracts 0xC00 (T_RVA-T_OFF)
        disp = np.frombuffer(d, dtype=np.int32, count=1, offset=off + 1)[0]
        target = site + 5 + int(disp)
        s = cstring_at(target)
        if s:
            strs.setdefault(s, []).append(site)
    return strs

def callers_of(lo, hi):
    m = (T >= lo) & (T < hi)
    funcs = {}
    for s in S[m]:
        f = pd.floor(int(s))
        if f:
            funcs.setdefault(f[0], []).append(int(s))
    return funcs

def report(fname, flist, depth, maxdepth=3):
    for b, e_ in flist:
        strs = func_strings(b, e_)
        interesting = [s for s in strs if len(s) >= 4][:24]
        print(f"{'  '*depth}FUNC 0x{b:X}-0x{e_:X} (0x{e_-b:X}) strings: {interesting}")
        if depth >= maxdepth:
            continue
        callees = callers_of(b, e_)
        # dedupe
        items = sorted(set((fb, pd.find(fb)[1]) for fb in callees))
        # skip huge callee sets (that means this func is called by many)
        print(f"{'  '*depth}  <- {len(items)} caller funcs")
        for fb, fe in items[:12]:
            report(fname, [(fb, fe)], depth + 1, maxdepth)

L1 = [(0x19C0460, 0x19C06C8), (0x19CAB90, 0x19CB2A1), (0x11EF870, 0x11EF9F6),
      (0x26C11A0, 0x26C12AF), (0x324EFA0, 0x324F103), (0x346BD10, 0x346D68A)]

print("=" * 80)
print("UPLINK from TextPacketPayload handler (0x3242680-0x324C0BA)")
print("=" * 80)
for b, e_ in L1:
    print(f"\n### branch 0x{b:X}")
    report('x', [(b, e_)], 0, maxdepth=3)
