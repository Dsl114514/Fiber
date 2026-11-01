#!/usr/bin/env python3
"""exe_extra3.py - locate UPX b_info block header in gdk_patch.dll and unpack."""
import struct
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GP = r"E:\mcb\bedrock_versions\1.26.3301\preload\gdk_patch.dll"
OUT = r"E:\mcb\Fiber\docs\gdk_patch_unpacked.bin"

with open(GP, "rb") as f:
    g = f.read()

print(f"file size = 0x{len(g):X}")
# b_info: sz_unc=0xA798 sz_cmp=0x3393 method=2 filter=0x49 cto=0x07 unused=0
pat = struct.pack("<IIBBBB", 0xA798, 0x3393, 2, 0x49, 0x07, 0x00)
hits = [m.start() for m in re.finditer(re.escape(pat), g)]
print(f"b_info pattern hits: {[hex(h) for h in hits]}")

# also p_info: p_filesize=0x6800
for m in re.finditer(re.escape(struct.pack("<I", 0x6800)), g):
    print(f"  u32 0x6800 at 0x{m.start():X}")

# hexdump around every hit and around 0x400
def hexdump(off, length, label):
    print(f"-- {label} (file 0x{off:X}..0x{off+length:X}) --")
    for r in range(0, length, 16):
        row = g[off+r:off+r+16]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
        print(f"  0x{off+r:04X}: {row.hex(' ')}  |{asc}|")

hexdump(0x400, 0x60, "UPX1 start")
for h in hits:
    hexdump(max(0, h-32), 64, f"b_info hit @0x{h:X}")
hexdump(0x3C0, 0x60, "around l_info")
hexdump(0x37A0, 0x60, "entry point area (EP rva 0xC3A0 -> file 0x37A0)")

if hits:
    b = hits[0]
    sz_unc, sz_cmp = struct.unpack_from("<II", g, b)
    print(f"\nusing block @0x{b:X}: sz_unc=0x{sz_unc:X} sz_cmp=0x{sz_cmp:X}")

    def nrv2b_decompress(src):
        bb = bc = ip = 0
        dst = bytearray()
        last_m_off = 1
        def getbit():
            nonlocal bb, bc, ip
            if bc == 0:
                bb = struct.unpack_from("<I", src, ip)[0]
                ip += 4
                bc = 32
            bc -= 1
            return (bb >> bc) & 1
        while True:
            while getbit():
                dst.append(src[ip]); ip += 1
            m_off = 1
            while True:
                m_off = m_off * 2 + getbit()
                if getbit():
                    break
                m_off = (m_off - 1) * 2 + getbit()
            if m_off == 2:
                m_off = last_m_off
            else:
                m_off = (m_off - 3) * 256 + src[ip]; ip += 1
                if m_off == 0xFFFFFFFF:
                    break
                m_off += 1
                last_m_off = m_off
            m_len = getbit()
            m_len = m_len * 2 + getbit()
            if m_len == 0:
                m_len += 1
                while True:
                    m_len = m_len * 2 + getbit()
                    if getbit():
                        break
                m_len += 2
            if m_off > 0xD00:
                m_len += 1
            dst.append(dst[-m_off])
            dst.append(dst[-m_off])
            for _ in range(m_len):
                dst.append(dst[-m_off])
            if len(dst) > sz_unc + 0x1000:
                raise ValueError("runaway")
        return bytes(dst), ip

    src = g[b+12:b+12+sz_cmp]
    out, ip = nrv2b_decompress(src)
    print(f"decompressed 0x{len(out):X} bytes, consumed 0x{ip:X} of 0x{sz_cmp:X}")
    if len(out) != sz_unc:
        print(f"!! size mismatch (expected 0x{sz_unc:X})")
    with open(OUT, "wb") as f:
        f.write(out)
    print(f"wrote {OUT}")

    # strings
    print("\n== strings in decompressed data (>=5) ==")
    for m in re.finditer(rb"[\x20-\x7E]{5,}", out):
        print(f"   0x{m.start():05X}: {m.group().decode('ascii')[:140]}")
