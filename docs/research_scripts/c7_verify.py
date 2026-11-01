#!/usr/bin/env python3
"""c7_verify.py - Verify MinecraftGame::update candidate:
1) code refs (rip-rel) to the profiler record slots (they use lea scope-rec)
2) callers/callees of 0x87AB10 / 0x87AC90 / 0x8071980
3) prologue + internal call summary of 0x87AC90
"""
import sys, struct
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
S = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_S.npy')
T = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_T.npy')

RECORDS = {
    0xDBDADC0: 'MG::update rec',
    0xDBDADB8: 'MG::update file',
    0xDBDADE0: 'MG::_update rec',
    0xDBDAE60: 'MG::startFrame rec',
    0xDBDAEA0: 'MG::endFrame rec',
    0xDBDAEC0: 'MG::onTick rec',
    0xDCC7390: 'ServerInstance::_update rec',
    0xDCC8178: 'ServerLevel::_subTick rec',
}

targets = np.array(sorted(RECORDS), dtype=np.int64)
hits = sc.scan_riprel_all(targets)
print("== Code refs to profiler record slots ==")
for site_end, tgt, disp in hits:
    f = pd.floor(site_end)
    print(f"  site 0x{site_end:X} -> {RECORDS[tgt]} | in func 0x{f[0]:X}-0x{f[1]:X}")

def callers(lo, hi):
    m = (T >= lo) & (T < hi)
    out = {}
    for s in S[m]:
        f = pd.floor(int(s))
        if f:
            out.setdefault(f[0], []).append(int(s))
    return out

def callees(lo, hi):
    m = (S >= lo) & (S < hi)
    tg = T[m]
    out = {}
    for t in tg:
        f = pd.floor(int(t))
        if f:
            out.setdefault(f[0], f[1])
    return out

for cand in (0x87AB10, 0x87AC90, 0x8071980):
    f = pd.find(cand)
    print(f"\n===== candidate 0x{cand:X} (func 0x{f[0]:X}-0x{f[1]:X}, sz 0x{f[1]-f[0]:X}) =====")
    cl = callers(f[0], f[1])
    print(f"  callers: {len(cl)}")
    for b, sites in sorted(cl.items(), key=lambda kv: -len(kv[1]))[:12]:
        fe = pd.find(b)
        print(f"    caller func 0x{b:X}-0x{fe[1]:X} (sz 0x{fe[1]-b:X}) sites={len(sites)}: {[hex(s) for s in sites[:6]]}")
    ce = callees(f[0], f[1])
    print(f"  distinct callees: {len(ce)}")
    for b, e in sorted(ce.items())[:40]:
        print(f"    callee 0x{b:X}-0x{e:X} (0x{e-b:X})")
