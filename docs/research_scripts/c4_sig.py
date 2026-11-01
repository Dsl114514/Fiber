#!/usr/bin/env python3
"""c4_sig.py - Exact-signature string lookup + rip-relative xref to find the
functions that own these strings (they pass them to loggers/profilers).
"""
import sys, re
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data

def find_exact(s):
    """All file offsets of exact byte string s."""
    b = s.encode('ascii')
    out = []
    start = 0
    while True:
        h = d.find(b, start)
        if h < 0:
            break
        out.append(h)
        start = h + 1
    return out

SIGS = [
    'void __cdecl MinecraftGame::onTick(void)',
    'virtual void __cdecl MinecraftGame::update(void)',
    'void __cdecl MinecraftGame::update(void)',
    'void __cdecl Minecraft::update(void)',
    'Minecraft::update(void)',
    'void __cdecl MinecraftGame::startFrame(void)',
    'void __cdecl MinecraftGame::endFrame(void)',
    'void __cdecl MinecraftGame::_update(void)',
    'void __cdecl ServerInstance::_update(void)',
    'virtual void __cdecl ServerLevel::_subTick(void)',
    'void __cdecl ServerNetworkHandler::tick(void)',
    'ServerNetworkHandler::tick(void)',
    'void __cdecl NetworkHandler::tick(void)',
    'Level::tick(void)',
    'void __cdecl Level::tick(void)',
    'Minecraft::startClientSubTick',
    'void __cdecl MinecraftGame::run(void)',
    'MinecraftGame::run(',
    'waitForPreviousFrame(void)',
]

sig_rvas = {}
for s in SIGS:
    offs = find_exact(s)
    for h in offs:
        rva = pe.off2rva(h)
        if rva > 0:
            sig_rvas.setdefault(s, []).append(rva)

for s, rv in sig_rvas.items():
    print(f"{s!r}: {[hex(x) for x in rv]}")

# xref: which functions reference these strings?
print("\n" + "=" * 80)
all_targets = sorted({r for v in sig_rvas.values() for r in v})
hits = sc.scan_riprel_all(np.array(all_targets, dtype=np.int64))
print(f"rip-relative refs found: {len(hits)}")
by_func = {}
for site_end, target, disp in hits:
    f = pd.floor(site_end)
    if f:
        by_func.setdefault((f[0], f[1]), set()).add(target)
for (b, e), tg in sorted(by_func.items()):
    tstrs = []
    for t in tg:
        for s, rv in sig_rvas.items():
            if t in rv:
                tstrs.append(s)
                break
    print(f"  func 0x{b:X}-0x{e:X} (0x{e-b:X}) refs: {tstrs}")

import json
with open(r'E:\mcb\Fiber\docs\research_scripts\c4_sigrvas.json', 'w') as f:
    json.dump({s: [hex(x) for x in v] for s, v in sig_rvas.items()}, f, indent=1)
