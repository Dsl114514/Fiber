#!/usr/bin/env python3
"""c11_rtti.py - Find MinecraftGame vftables via RTTI; check which slots hold the
candidate function pointers; also callers/strings of ServerInstance::_update big body."""
import sys, struct
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
IB = pe.image_base
rd = pe.sec_by_name('.rdata')
S = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_S.npy')
T = np.load(r'E:\mcb\Fiber\docs\research_scripts\callgraph_T.npy')

def find_all(b):
    out, start = [], 0
    while True:
        h = d.find(b, start)
        if h < 0: break
        out.append(h); start = h + 1
    return out

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

CANDS = [0x8B5A30, 0x879E10, 0x87A530, 0x87AB10, 0x87AC90,
         0x1D5E6B0, 0x1D5E740, 0x1D5E7D0, 0x1D60D40,
         0x1D64ED0, 0x1D65410, 0x1D77260]

CLASSES = ['MinecraftGame', 'IMinecraftGame', 'ServerInstance', 'ServerLevel', 'Level@@']

for cls in CLASSES:
    pat = f'.?AV{cls}'.encode()
    offs = find_all(pat)
    print(f"\n### TD '{cls}': {len(offs)} hit(s)")
    for h in offs[:6]:
        # TD: [vftable 8][spare 8][name...]; name starts at h (includes .?AV)
        td_off = h - 16
        if td_off < 0: continue
        td_rva = pe.off2rva(td_off)
        if td_rva < 0: continue
        nm_end = d.find(b'\x00', h)
        nm = d[h:nm_end].decode('ascii', 'replace')
        # find COLs: DWORD == td_rva in .rdata
        rd_off = rd['raddr']
        arr = np.frombuffer(d, dtype=np.uint32, count=rd['rsize'] // 4, offset=rd_off)
        col_sites = np.flatnonzero(arr == td_rva)
        # for each, check QWORD ptr-to-COL (VA) right before -> vftable
        vftables = []
        for cs in col_sites:
            col_rva = rd['vaddr'] + int(cs) * 4
            # search QWORD == IB+col_rva in rdata
            needle = struct.pack('<Q', IB + col_rva)
            q = d.find(needle, rd_off, rd_off + rd['rsize'])
            if q >= 0 and q % 8 == 0:
                vft_start_rva = pe.off2rva(q) + 8  # vftable begins after COL ptr
                vftables.append((col_rva, vft_start_rva))
        print(f"  TD rva 0x{td_rva:X} name='{nm}' COLs={len(col_sites)} vftables={len(vftables)}")
        for col_rva, vft in vftables[:4]:
            # dump slots
            vo = pe.rva2off(vft)
            slots = []
            for k in range(24):
                v = struct.unpack_from('<Q', d, vo + k * 8)[0]
                vr = v - IB
                tsec = pe.sec_by_name('.text')
                mark = ''
                if tsec['vaddr'] <= vr < tsec['vaddr'] + tsec['vsize']:
                    f = pd.find(vr)
                    mark = f"-> 0x{vr:X} " + (f"[fn 0x{f[0]:X}-0x{f[1]:X}]" if f and f[0] == vr else f"[mid 0x{f[0]:X}]" if f else "[?]")
                    if vr in CANDS:
                        mark += " <<< CANDIDATE"
                slots.append(f"    vtbl+{k*8:#x} rva 0x{vft + k*8:X}: {mark}")
            print(f"  vftable rva 0x{vft:X} (COL 0x{col_rva:X}):")
            print('\n'.join(slots))

def callers(lo, hi):
    m = (T >= lo) & (T < hi)
    out = {}
    for s in S[m]:
        f = pd.floor(int(s))
        if f: out.setdefault(f[0], []).append(int(s))
    return out

for fn in (0x1D60D40, 0x1D5E7D0, 0x1D64ED0):
    f = pd.find(fn)
    cl = callers(f[0], f[1])
    print(f"\n### callers of 0x{fn:X} (0x{f[0]:X}-0x{f[1]:X}):")
    for b, sites in sorted(cl.items(), key=lambda kv: -len(kv[1]))[:8]:
        fe = pd.find(b)
        print(f"    0x{b:X}-0x{fe[1]:X} (sz 0x{fe[1]-b:X}) sites={[hex(x) for x in sites[:4]]}")
