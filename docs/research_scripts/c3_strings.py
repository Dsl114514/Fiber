#!/usr/bin/env python3
"""c3_strings.py - Search raw file for tick/mainloop-related name strings,
map file offsets -> RVA, then find code functions that rip-reference them.
"""
import sys, re
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data

PATTERNS = [
    (b'?tick@Minecraft', 'Minecraft::tick mangled'),
    (b'@Minecraft@@', 'Minecraft@@ (mangled methods)'),
    (b'?tick@Level', 'Level::tick mangled'),
    (b'?tick@ServerLevel', 'ServerLevel::tick'),
    (b'?tick@ClientLevel', 'ClientLevel::tick'),
    (b'?tick@ServerNetworkHandler', 'ServerNetworkHandler::tick'),
    (b'?tick@NetworkHandler', 'NetworkHandler::tick'),
    (b'?run@Minecraft', 'Minecraft::run'),
    (b'?update@Minecraft', 'Minecraft::update'),
    (b'Minecraft::tick', 'Minecraft::tick pretty'),
    (b'Level::tick', 'Level::tick pretty'),
    (b'ServerNetworkHandler::tick', 'SNH::tick pretty'),
    (b'Minecraft.cpp', 'Minecraft.cpp source path'),
    (b'startGame.cpp', 'startGame.cpp path'),
    (b'MinecraftGame', 'MinecraftGame'),
    (b'?tick@GameMode', 'GameMode::tick'),
    (b'?tick@ClientInstance', 'ClientInstance::tick'),
    (b'?tick@Dimension', 'Dimension::tick'),
    (b'?tick@SubChunk', 'SubChunk tick'),
    (b'LevelTick', 'LevelTick'),
    (b'?_tick@', '_tick mangled'),
    (b'tickingAreas', 'tickingAreas'),
    (b'TickingAreas', 'TickingAreas'),
    (b'?stepOnTicking', 'Ticking?'),
    (b'MinecraftPacketIds', 'MinecraftPacketIds'),
    (b'?handle@Packet', 'Packet::handle'),
    (b'?_handle@Packet', 'Packet::_handle'),
]

found = []
for pat, desc in PATTERNS:
    start = 0
    count = 0
    while count < 40:
        h = d.find(pat, start)
        if h < 0:
            break
        rva = pe.off2rva(h)
        # extract a readable window around
        ctx = d[max(0, h - 40):h + len(pat) + 60]
        ctx_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        found.append((pat, desc, h, rva, ctx_s))
        start = h + 1
        count += 1

# summarize: group by pattern
for pat, desc, h, rva, ctx_s in found:
    print(f"[{desc}] file=0x{h:X} rva={hex(rva) if rva>0 else '?'}")
    print(f"    ctx: ...{ctx_s}...")
print(f"\ntotal {len(found)} hits")

# save unique string RVAs for xref scan
uniq = {}
for pat, desc, h, rva, ctx_s in found:
    if rva > 0:
        uniq.setdefault(rva, (desc, ctx_s))
import json
with open(r'E:\mcb\Fiber\docs\research_scripts\c3_hits.json', 'w') as f:
    json.dump({hex(k): v for k, v in uniq.items()}, f, indent=1)
print(f"unique RVAs: {len(uniq)}")
