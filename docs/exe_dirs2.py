#!/usr/bin/env python3
"""exe_dirs2.py - raw hexdump of data directory array + .addImp layout analysis."""
import struct
import re

EXE = r"E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe"
with open(EXE, "rb") as f:
    data = f.read()

e = struct.unpack_from("<I", data, 0x3C)[0]
opt = e + 24
nsec = struct.unpack_from("<H", data, e + 6)[0]

sections = []
off = opt + 0xF0
for i in range(nsec):
    name = data[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
    vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off+8)
    sections.append((name, vaddr, vsize, rptr, rsize))
    off += 40

def rva2off(r):
    for n, va, vs, rp, rs in sections:
        if va <= r < va + max(vs, rs):
            return rp + (r - va), n
    return None, None

def off2rva(o):
    for n, va, vs, rp, rs in sections:
        if rp <= o < rp + rs:
            return va + (o - rp), n
    return None, None

print("== RAW data directory bytes (16 x 8) ==")
dd_off = opt + 0x60
n = struct.unpack_from("<Q", data, opt + 0x58)[0]
print(f"NumberOfRvaAndSizes = {n}")
for i in range(16):
    rva, size = struct.unpack_from("<II", data, dd_off + i*8)
    o, sn = rva2off(rva) if rva else (None, None)
    print(f"  [{i:2d}] raw: rva=0x{rva:08X} size=0x{size:08X}   ->file={('0x%08X'%o) if o else '-':>10s} sec={sn}")

print("\n== .addImp head (file 0x11701000, 0x120 bytes) ==")
base = 0x11701000
for r in range(0, 0x120, 16):
    row = data[base+r:base+r+16]
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
    print(f"  +0x{r:04X} (f=0x{base+r:08X} rva=0x{0x11A13000+r:08X}): {row.hex(' ')}  |{asc}|")

print("\n== scan .addImp for IMAGE_IMPORT_DESCRIPTOR-like 20-byte structs ==")
ai_start, ai_size = 0x11701000, 0x02D0F800
ai_rva = 0x11A13000
buf = data[ai_start:ai_start+ai_size]
found = []
for k in range(0, min(0x2000, len(buf)-20), 4):
    oft, tstamp, fwd, name_rva, iat = struct.unpack_from("<IIIII", buf, k)
    if name_rva == 0 and oft == 0 and iat == 0:
        continue
    # name must point inside .addImp to an ascii dll string
    if ai_rva <= name_rva < ai_rva + ai_size:
        no = ai_start + (name_rva - ai_rva)
        end = data.find(b"\x00", no, no+64)
        if end > no and end - no < 64:
            nm = data[no:end]
            if re.fullmatch(rb"[\x20-\x7E]+\.dll", nm, re.I):
                found.append((k, oft, name_rva, iat, nm.decode()))
for k, oft, name_rva, iat, nm in found[:40]:
    print(f"  desc@.addImp+0x{k:04X} (rva=0x{ai_rva+k:08X}) name='{nm}' OFT=0x{oft:08X} IAT=0x{iat:08X}")
print(f"  total {len(found)}")

print("\n== around PreloadCpp.dll string (file 0x11701500-0x11701A00) ==")
for r in range(0x500, 0xA00, 16):
    row = data[base+r:base+r+16]
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
    print(f"  +0x{r:04X} (f=0x{base+r:08X} rva=0x{0x11A13000+r:08X}): {row.hex(' ')}  |{asc}|")

print("\n== file tail (last 0x200 bytes) - overlay check ==")
tail = len(data) - 0x200
for r in range(0, 0x200, 16):
    row = data[tail+r:tail+r+16]
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
    print(f"  f=0x{tail+r:08X}: {row.hex(' ')}  |{asc}|")
