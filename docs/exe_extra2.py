#!/usr/bin/env python3
"""exe_extra2.py - proper UPX NRV2B unpack of gdk_patch.dll, then parse the
unpacked original image (headers, exports, imports, strings)."""
import struct
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GP = r"E:\mcb\bedrock_versions\1.26.3301\preload\gdk_patch.dll"
OUT = r"E:\mcb\Fiber\docs\gdk_patch_unpacked.bin"


def nrv2b_decompress(src):
    """Canonical UCL NRV2B_LE32 decompressor. Returns (dst, consumed)."""
    bb = 0
    bc = 0
    ip = 0
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
        # copy m_len+2 bytes
        dst.append(dst[-m_off])
        dst.append(dst[-m_off])
        for _ in range(m_len):
            dst.append(dst[-m_off])
        if len(dst) > 0x200000:
            raise ValueError("runaway output")
    return bytes(dst), ip


with open(GP, "rb") as f:
    g = f.read()

# find all block headers: {u32 sz_unc, u32 sz_cmp, u8 method==2, u8 filter, u8 cto, u8 unused}
print("== scanning for NRV2B block headers ==")
blocks = []
for o in range(0, len(g) - 12):
    sz_unc, sz_cmp = struct.unpack_from("<II", g, o)
    mth, flt, cto, unused = g[o+8], g[o+9], g[o+10], g[o+11]
    if mth == 2 and 0x200 < sz_unc <= 0xA800 and 0x100 < sz_cmp <= sz_unc and unused == 0:
        blocks.append((o, sz_unc, sz_cmp, flt, cto))
        print(f"  candidate block @0x{o:X}: sz_unc=0x{sz_unc:X} sz_cmp=0x{sz_cmp:X} filter={flt} cto=0x{cto:02X}")

full = bytearray()
consumed_report = []
for o, sz_unc, sz_cmp, flt, cto in blocks:
    try:
        out, ip = nrv2b_decompress(g[o+12:o+12+sz_cmp+64])
        print(f"  block @0x{o:X}: decompressed 0x{len(out):X} bytes (consumed 0x{ip:X}, sz_cmp=0x{sz_cmp:X})")
        if len(out) != sz_unc:
            print(f"    !! size mismatch, expected 0x{sz_unc:X}")
        full.extend(out)
        consumed_report.append((o, len(out)))
    except Exception as ex:
        print(f"  block @0x{o:X}: FAILED {ex}")

print(f"\ntotal decompressed: {len(full):,} bytes")
if full[:2] == b"MZ":
    print("unpacked image starts with MZ -- good")
    with open(OUT, "wb") as f:
        f.write(full)
else:
    print("first 32 bytes:", full[:32].hex(" "))
    with open(OUT, "wb") as f:
        f.write(full)

# parse unpacked image if PE
if full[:2] == b"MZ":
    e = struct.unpack_from("<I", full, 0x3C)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", full, opt)[0]
    is64 = magic == 0x20B
    ddbase = opt + (0x70 if is64 else 0x60)
    nsec = struct.unpack_from("<H", full, e + 6)[0]
    sections = []
    off = opt + (0xF0 if is64 else 0xE0)
    for i in range(nsec):
        name = full[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", full, off+8)
        sections.append((name, vaddr, vsize, rptr, rsize))
        off += 40

    def rva2off(r):
        for n, va, vs, rp, rs in sections:
            if va <= r < va + max(vs, rs):
                return rp + (r - va), n
        return None, None

    print("\n== unpacked gdk_patch sections ==")
    for n, va, vs, rp, rs in sections:
        print(f"   {n:8s} rva=0x{va:X} vsize=0x{vs:X} file=0x{rp:X}")
    ts = struct.unpack_from("<I", full, e + 8)[0]
    print(f"   timestamp=0x{ts:X}  characteristics=0x{struct.unpack_from('<H', full, e+22)[0]:X}  dllchars=0x{struct.unpack_from('<H', full, opt+70)[0]:X}")

    exp_rva, _ = struct.unpack_from("<II", full, ddbase)
    print(f"\n== unpacked exports (dir rva=0x{exp_rva:X}) ==")
    if exp_rva:
        eo, _ = rva2off(exp_rva)
        flags, tstamp, mj, mn, name_rva, base, nfuncs, nnames, af, an, ao = struct.unpack_from("<IIHHIIIIIII", full, eo)
        no, _ = rva2off(name_rva)
        print(f"   dll='{full[no:full.index(b'\x00', no)].decode()}' nfuncs={nfuncs} nnames={nnames}")
        if an:
            an_off, _ = rva2off(an)
            ao_off, _ = rva2off(ao) if ao else (None, None)
            af_off, _ = rva2off(af)
            for k in range(nnames):
                nrva = struct.unpack_from("<I", full, an_off + k*4)[0]
                noff, _ = rva2off(nrva)
                nm = full[noff:full.index(b"\x00", noff)].decode("ascii", "replace")
                oi = struct.unpack_from("<H", full, ao_off + k*2)[0] if ao_off else k
                frva = struct.unpack_from("<I", full, af_off + oi*4)[0] if af_off else 0
                print(f"   export '{nm}' ord={base+oi} rva=0x{frva:X}")

    imp_rva, _ = struct.unpack_from("<II", full, ddbase + 8)
    print(f"\n== unpacked imports (dir rva=0x{imp_rva:X}) ==")
    if imp_rva:
        io, _ = rva2off(imp_rva)
        k = 0
        while True:
            oft, t2, fwd, name_rva, iat = struct.unpack_from("<IIIII", full, io + k*20)
            if not name_rva:
                break
            no, _ = rva2off(name_rva)
            dll = full[no:full.index(b"\x00", no)].decode("ascii", "replace")
            thunk = oft or iat
            to, _ = rva2off(thunk)
            funcs = []
            m = 0
            while to is not None:
                val = struct.unpack_from("<Q" if is64 else "<I", full, to + m*(8 if is64 else 4))[0]
                if val == 0:
                    break
                hi = 1 << 63 if is64 else 1 << 31
                if val & hi:
                    funcs.append(f"ord{val & 0xFFFF}")
                else:
                    ho, _ = rva2off(val & 0x7FFFFFFF)
                    if ho:
                        funcs.append(full[ho+2:full.index(b"\x00", ho+2)].decode("ascii", "replace"))
                m += 1
            print(f"   {dll}: {', '.join(funcs)}")
            k += 1

    print("\n== unpacked strings (>=5 chars, all sections) ==")
    for m in re.finditer(rb"[\x20-\x7E]{5,}", full):
        s = m.group().decode("ascii")
        if s.startswith(".") and ("text" in s or "rdata" in s or "data" in s):
            continue
        print(f"   0x{m.start():05X}: {s[:140]}")
