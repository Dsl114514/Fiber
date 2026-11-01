#!/usr/bin/env python3
"""c6_table.py - Dump the profiler scope table as structured records.
Record guess: 8-byte slots; classify each slot: code-VA (.text), string-VA (.rdata cstr), int.
"""
import sys, struct
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
IB = pe.image_base
t = pe.sec_by_name('.text')
rd = pe.sec_by_name('.rdata')

def classify(v):
    vr = v - IB
    if t['vaddr'] <= vr < t['vaddr'] + t['vsize']:
        f = pd.find(vr)
        if f:
            return f"CODE func 0x{vr:X}-0x{f[1]:X} (sz 0x{f[1]-f[0]:X})"
        return f"CODE 0x{vr:X} (no pdata)"
    if rd['vaddr'] <= vr < rd['vaddr'] + rd['vsize']:
        off = pe.rva2off(vr)
        end = d.find(b'\x00', off, off + 90)
        if end > off:
            s = d[off:end]
            if len(s) >= 3 and all(32 <= c < 127 for c in s):
                return f'STR "{s.decode()[:80]}"'
            return f"DATA 0x{vr:X} ({s[:12].hex()})"
        return f"DATA 0x{vr:X}"
    if 0 < v < 0x100000000:
        return f"int {v} (0x{v:X})"
    return f"? 0x{v:016X}"

def dump_region(lo_rva, hi_rva):
    off_lo = pe.rva2off(lo_rva)
    n = hi_rva - lo_rva
    print(f"\n===== region rva 0x{lo_rva:X}-0x{hi_rva:X} =====")
    for o in range(0, n, 8):
        v = struct.unpack_from('<Q', d, off_lo + o)[0]
        c = classify(v)
        print(f"  0x{lo_rva + o:X}: {c}")

# The three discovered record neighborhoods
dump_region(0xDBDAD80, 0xDBDAF00)
dump_region(0xDCC7350, 0xDCC7420)
dump_region(0xDCC8120, 0xDCC81C0)

# Candidates from table
for rva in (0x87AB10, 0x87AC90, 0x1D5E740, 0x1D5E7D0, 0x1643F80, 0x16459E0, 0x1D77260):
    f = pd.find(rva)
    print(f"\n0x{rva:X}: pdata={tuple(hex(x) for x in f) if f else None}")
