#!/usr/bin/env python3
"""exe_extra4.py - gdk_patch.dll: compressed stream starts at file 0x400 (right after
l_info @0x3E0 which carries u_len=0xA798, c_len=0x3393, method=2 NRV2B, filter=0x49)."""
import struct
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GP = r"E:\mcb\bedrock_versions\1.26.3301\preload\gdk_patch.dll"
OUT = r"E:\mcb\Fiber\docs\gdk_patch_unpacked.bin"

with open(GP, "rb") as f:
    g = f.read()

sz_unc = 0xA798
sz_cmp = 0x3393


def nrv2b_decompress(src, expected):
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
    try:
        while True:
            while getbit():
                dst.append(src[ip]); ip += 1
                if len(dst) == expected:
                    return bytes(dst), ip
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
                    return bytes(dst), ip  # EOF
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
            if len(dst) == expected:
                return bytes(dst), ip
            if len(dst) > expected:
                raise ValueError(f"overshoot: {len(dst):X} > {expected:X}")
    except (IndexError, struct.error) as ex:
        print(f"stopped: {ex} at dst=0x{len(dst):X} ip=0x{ip:X}")
        return bytes(dst), ip


src = g[0x400:0x400 + sz_cmp + 64]
out, ip = nrv2b_decompress(src, sz_unc)
print(f"decompressed 0x{len(out):X} bytes (expected 0x{sz_unc:X}), consumed 0x{ip:X} of 0x{sz_cmp:X}")
with open(OUT, "wb") as f:
    f.write(out)
print(f"wrote {OUT}")
print("first 64 bytes:", out[:64].hex(" "))

# check MZ and parse
if out[:2] == b"MZ":
    e = struct.unpack_from("<I", out, 0x3C)[0]
    print(f"PE header at 0x{e:X}: {out[e:e+4]}")
    print("\n== ascii strings (>=5) in unpacked image ==")
    for m in re.finditer(rb"[\x20-\x7E]{5,}", out):
        s = m.group().decode("ascii")
        print(f"   0x{m.start():05X}: {s[:140]}")
