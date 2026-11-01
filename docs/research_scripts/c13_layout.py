#!/usr/bin/env python3
"""c13_layout.py - Dump profiler table records: anchor on (file,name) QWORD pairs,
print 6 slots before and 6 after, across the two windows."""
import sys, struct
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
IB = pe.image_base
rd = pe.sec_by_name('.rdata')

def rstr(rva, maxlen=100):
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

def slotlabel(v):
    vr = v - IB
    tsec = pe.sec_by_name('.text')
    if tsec['vaddr'] <= vr < tsec['vaddr'] + tsec['vsize']:
        f = pd.find(vr)
        if f and f[0] == vr:
            return f"FN 0x{vr:X}(sz 0x{f[1]-f[0]:X})"
        if f:
            return f"mid 0x{vr:X}@0x{f[0]:X}"
        return f"CODE? 0x{vr:X}"
    s = rstr(vr) if rd['vaddr'] <= vr < rd['vaddr'] + rd['vsize'] else None
    if s:
        return f'STR "{s[:60]}"'
    return f"0x{v:012X}"

def dump_records(lo, hi):
    off = pe.rva2off(lo)
    n = (hi - lo) // 8
    q = np.frombuffer(d, dtype='<u8', count=n, offset=off).astype(np.uint64)
    rvas = lo + np.arange(0, n * 8, 8)
    # find name slots: STR with ' __cdecl ' or ending in '(void)' style
    names = []
    for i in range(n):
        v = int(q[i]) - IB
        if rd['vaddr'] <= v < rd['vaddr'] + rd['vsize']:
            s = rstr(v)
            if s and ('(' in s and ')' in s) and ('::' in s or '__cdecl' in s):
                names.append((i, s))
    print(f"window 0x{lo:X}-0x{hi:X}: {len(names)} signature-ish names")
    seen_spans = []
    for i, s in names:
        lo_i = max(0, i - 7)
        hi_i = min(n, i + 4)
        # skip overlapping dumps
        if seen_spans and lo_i <= seen_spans[-1][1]:
            continue
        seen_spans.append((lo_i, hi_i))
        print(f"\n--- record @ rva 0x{rvas[i]:X} name=\"{s[:70]}\"")
        for k in range(lo_i, hi_i):
            mark = ' <-- name' if k == i else ''
            print(f"   0x{rvas[k]:X}: {slotlabel(int(q[k]))}{mark}")

dump_records(0xDBD0000, 0xDBDC000)
dump_records(0xDCC6000, 0xDCC8400)
