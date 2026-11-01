#!/usr/bin/env python3
"""c10_harvest.py - Harvest the profiler/whisker tables: any QWORD in candidate
.rdata windows that points into .text AND lies within 40 bytes of a QWORD pointing
to a signature-style string. Build code->name map. Print tick/update/frame entries.
"""
import sys, struct, re
sys.path.insert(0, r'E:\mcb\Fiber\docs\research_scripts')
import numpy as np
from ml_lib import load

pe, pd, sc = load()
d = pe.data
IB = pe.image_base
t = pe.sec_by_name('.text')
rd = pe.sec_by_name('.rdata')

WINDOWS = [
    (0xDBD0000, 0xDBDC000),
    (0xDCC6000, 0xDCC8400),
]

def rstr(rva, maxlen=110):
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

SIGRE = re.compile(r'__cdecl [A-Za-z_][A-Za-z0-9_:~]*::')

pairs = {}  # code_rva -> set of names
for lo, hi in WINDOWS:
    off = pe.rva2off(lo)
    n = hi - lo
    q = np.frombuffer(d, dtype='<u8', count=n // 8, offset=off).astype(np.uint64)
    rvas = lo + np.arange(0, n, 8)
    in_text = (q - IB >= t['vaddr']) & (q - IB < t['vaddr'] + t['vsize'])
    is_str = np.zeros(len(q), dtype=bool)
    strv = {}
    for i in range(len(q)):
        v = int(q[i]) - IB
        s = rstr(v) if rd['vaddr'] <= v < rd['vaddr'] + rd['vsize'] else None
        if s and SIGRE.search(s):
            is_str[i] = True
            strv[i] = s
    for i in np.flatnonzero(in_text):
        code = int(q[i]) - IB
        # look +/- 5 slots for a name
        for k in range(-5, 6):
            j = i + k
            if 0 <= j < len(q) and is_str[j]:
                pairs.setdefault(code, set()).add(strv[j])

print(f"code->name pairs harvested: {len(pairs)}")
interesting = {}
for code, names in sorted(pairs.items()):
    for nm in names:
        if re.search(r'(tick|update|Frame|run)\(', nm, re.I):
            interesting.setdefault(code, set()).add(nm)

for code, names in sorted(interesting.items()):
    f = pd.find(code)
    fs = f"func 0x{f[0]:X}-0x{f[1]:X} (sz 0x{f[1]-f[0]:X})" if f else "no-pdata"
    print(f"\n  CODE 0x{code:X} [{fs}]")
    for nm in sorted(names):
        print(f"      name: {nm}")

# save full dict
import json
json.dump({hex(k): sorted(v) for k, v in pairs.items()},
          open(r'E:\mcb\Fiber\docs\research_scripts\c10_pairs.json', 'w'), indent=1)
