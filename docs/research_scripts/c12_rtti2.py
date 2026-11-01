#!/usr/bin/env python3
"""c12_rtti2.py - RTTI retry with '?AV' prefix; then vftable slot scan for candidates."""
import sys, struct
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
IB = pe.image_base
rd = pe.sec_by_name('.rdata')

def find_all(b, limit=20):
    out, start = [], 0
    while len(out) < limit:
        h = d.find(b, start)
        if h < 0: break
        out.append(h); start = h + 1
    return out

CANDS = {0x8B5A30: 'MinecraftGame::update?A', 0x879E10: 'MG::update n1', 0x87A530: 'MG::update n2',
         0x87AB10: 'MG::update n3', 0x87AC90: 'MG::update BIG',
         0x1D5E6B0: 'SI::_update n1', 0x1D5E740: 'SI::_update n2', 0x1D5E7D0: 'SI::_update n3',
         0x1D60D40: 'SI::_update BIG', 0x1D64ED0: 'SL::_subTick n1', 0x1D65410: 'SL::_subTick n2',
         0x1D77260: 'SL::_subTick n3', 0x1643EA0: 'SL::_subTick noP1', 0x1643F80: 'SL::_subTick noP2',
         0x16459E0: 'SL::_subTick noP3'}

# 1) locate TD structures: search '?AVClassName@@' occurrences in whole file
CLASSES = ['MinecraftGame@@', 'IMinecraftGame@@', 'ServerInstance@@', 'ServerLevel@@', 'Level@@', 'Minecraft@@']
tds = {}
for cls in CLASSES:
    pat = f'?AV{cls}'.encode()
    offs = find_all(pat)
    for h in offs:
        nm_end = d.find(b'\x00', h)
        nm = d[h:nm_end].decode('ascii', 'replace')
        # TD struct starts 16 bytes before name
        td_off = h - 16
        td_rva = pe.off2rva(td_off)
        if td_rva > 0:
            tds.setdefault(cls, []).append((td_rva, h, nm))

for cls, lst in tds.items():
    print(f"### {cls}: {len(lst)} TD(s)")
    for td_rva, h, nm in lst[:8]:
        print(f"    TD rva 0x{td_rva:X} name='{nm[:70]}'")

# 2) For each TD, find COL (u32==td_rva in rdata), then QWORD VA->COL; vftable after
print("\n" + "=" * 70)
rd_arr = np.frombuffer(d, dtype=np.uint32, count=rd['rsize'] // 4, offset=rd['raddr'])
for cls, lst in tds.items():
    for td_rva, h, nm in lst[:8]:
        col_sites = np.flatnonzero(rd_arr == td_rva)
        for cs in col_sites[:4]:
            col_rva = rd['vaddr'] + int(cs) * 4
            needle = struct.pack('<Q', IB + col_rva)
            q = d.find(needle, rd['raddr'], rd['raddr'] + rd['rsize'])
            if q < 0 or q % 8 != 0:
                continue
            vft = pe.off2rva(q) + 8
            vo = pe.rva2off(vft)
            if vo < 0:
                continue
            print(f"\n== {nm[:50]} vftable rva 0x{vft:X} ==")
            hits = []
            for k in range(40):
                v = struct.unpack_from('<Q', d, vo + k * 8)[0]
                vr = v - IB
                if vr in CANDS:
                    hits.append((k, vr))
            if hits:
                for k, vr in hits:
                    print(f"   SLOT vtbl+0x{k*8:X} (rva 0x{vft + k*8:X}) = 0x{vr:X}  {CANDS[vr]}  <<<")
            else:
                # print first few slots for context
                row = []
                for k in range(10):
                    v = struct.unpack_from('<Q', d, vo + k * 8)[0]
                    row.append(hex(v - IB) if 0x1000 <= v - IB < 0x1100000 else hex(v))
                print(f"   (no candidates in first 40 slots) first slots: {row}")
