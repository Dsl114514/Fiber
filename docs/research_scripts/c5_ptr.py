#!/usr/bin/env python3
"""c5_ptr.py - Find pointer-table slots: 8-byte VAs anywhere in the image that
point at the signature strings; dump neighboring slots (likely fn-ptr + name pairs).
"""
import sys, struct
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
IB = pe.image_base

SIGS = {
    'onTick': 0xE3C941F,
    'startFrame': 0xE3C9970,
    'endFrame': 0xE3C99E3,
    'MG_update': 0xE3C9852,
    'MG__update': 0xE3C97D8,
    'ServerInstance_update': 0xE3C9802,
    'Minecraft_update_str': 0xE3C983A,
    'ServerLevel_subTick': 0xE3C9448,
}

def va_scan(target_rva):
    """Find QWORDs anywhere in file equal to image_base+target_rva."""
    needle = struct.pack('<Q', IB + target_rva)
    out = []
    start = 0
    while True:
        h = d.find(needle, start)
        if h < 0:
            break
        out.append(h)
        start = h + 1
    return out

def slot_context(off):
    """Dump the 3 QWORDs before and after this slot with their RVAs."""
    lines = []
    for k in range(-3, 4):
        o = off + k * 8
        if o < 0 or o + 8 > len(d):
            continue
        v = struct.unpack_from('<Q', d, o)[0]
        rva = pe.off2rva(o)
        txt = ''
        # if v points into image, try read string
        vr = v - IB
        po = pe.rva2off(vr) if vr > 0 and vr < 0x1200000 else -1
        if po > 0:
            end = d.find(b'\x00', po, po + 80)
            if 0 < end - po < 80:
                try:
                    s = d[po:end].decode('ascii')
                    if all(32 <= c < 127 for c in s) and len(s) >= 4:
                        txt = ' "' + s[:70] + '"'
                except UnicodeDecodeError:
                    pass
        lines.append(f"    slot rva={hex(rva) if rva>0 else '?'}: 0x{v:016X} (rva {hex(vr) if vr>0 else '-'}){txt}")
    return '\n'.join(lines)

for name, rva in SIGS.items():
    slots = va_scan(rva)
    print(f"\n### {name} (string rva 0x{rva:X}) — {len(slots)} pointer slot(s)")
    for off in slots:
        fslot = pe.off2rva(off)
        print(f"  slot at file 0x{off:X} rva {hex(fslot) if fslot>0 else '?'}:")
        print(slot_context(off))
