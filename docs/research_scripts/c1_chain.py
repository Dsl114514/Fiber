#!/usr/bin/env python3
"""c1_chain.py - Trace callers of the TextPacketPayload handler function
(0x3242680 per .pdata, containing LEA ref to 'TextPacketPayload' at 0x3249CBE).
Find all direct E8/E9 references into that range; for each caller site find its
containing .pdata function; then repeat upward 3 levels.
"""
import sys, io, struct
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()

# Load full callgraph (may take a while for 230MB .text)
print("Building callgraph arrays ...", flush=True)
cg = sc.callgraph_targets()
S, T, K = cg
print(f"Direct E8/E9 sites: {len(S):,}", flush=True)

np.save(r'E:\mcb\Fiber\docs\research_scripts\callgraph_S.npy', S)
np.save(r'E:\mcb\Fiber\docs\research_scripts\callgraph_T.npy', T)
np.save(r'E:\mcb\Fiber\docs\research_scripts\callgraph_K.npy', K)

def callers_of(lo, hi):
    m = (T >= lo) & (T < hi)
    sites = S[m]
    funcs = {}
    for s in sites:
        f = pd.floor(int(s))
        if f:
            funcs.setdefault(f[0], []).append(int(s))
    return funcs

def describe(rva):
    f = pd.find(rva)
    return f"func 0x{f[0]:X}-0x{f[1]:X}" if f else "no pdata"

def level_report(level, rva_lo, rva_hi):
    print(f"\n{'='*70}\nLEVEL {level}: callers of [0x{rva_lo:X}-0x{rva_hi:X})\n{'='*70}")
    funcs = callers_of(rva_lo, rva_hi)
    print(f"Distinct caller functions: {len(funcs)}")
    for b, sites in sorted(funcs.items(), key=lambda kv: -len(kv[1])):
        f = pd.find(b)
        end = f[1] if f else b
        print(f"  caller func 0x{b:X}-0x{end:X} (size 0x{end-b:X}) sites={len(sites)}: "
              + ", ".join(f"0x{s:X}" for s in sites[:8]))
    return funcs

# Level 1: callers of TextPacketPayload handler range
L1 = level_report(1, 0x3242680, 0x324C0BA)
