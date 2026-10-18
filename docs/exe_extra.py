#!/usr/bin/env python3
"""exe_extra.py - TLS callbacks (VA-ImageBase), export dir parse, debug/PDB, and
UPX NRV2B unpack of gdk_patch.dll with string dump."""
import struct
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXE = r"E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe"
PC = r"E:\mcb\bedrock_versions\1.26.3301\PreloadCpp.dll"
GP = r"E:\mcb\bedrock_versions\1.26.3301\preload\gdk_patch.dll"
IMAGE_BASE = 0x140000000

class PE:
    def __init__(self, data):
        self.data = data
        e = struct.unpack_from("<I", data, 0x3C)[0]
        self.e = e
        self.opt = e + 24
        self.ddbase = self.opt + 0x70
        self.nsec = struct.unpack_from("<H", data, e+6)[0]
        self.sections = []
        off = self.opt + 0xF0
        for i in range(self.nsec):
            name = data[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off+8)
            self.sections.append((name, vaddr, vsize, rptr, rsize))
            off += 40
    def dir(self, i):
        return struct.unpack_from("<II", self.data, self.ddbase + i*8)
    def rva2off(self, r):
        for n, va, vs, rp, rs in self.sections:
            if va <= r < va + max(vs, rs):
                return rp + (r - va), n
        return None, None
    def off2rva(self, o):
        for n, va, vs, rp, rs in self.sections:
            if rp <= o < rp + rs:
                return va + (o - rp), n
        return None, None

with open(EXE, "rb") as f:
    data = f.read()
pe = PE(data)

# ---- TLS callbacks ----
tls_rva, tls_size = pe.dir(9)
to_, _ = pe.rva2off(tls_rva)
start, end, idxva, cbva = struct.unpack_from("<QQQQ", data, to_)
print(f"== TLS dir rva=0x{tls_rva:X}: callbacks VA=0x{cbva:X} ==")
if cbva:
    cb_rva = cbva - IMAGE_BASE
    co, csec = pe.rva2off(cb_rva)
    print(f"   callbacks rva=0x{cb_rva:X} file=0x{co:08X} sec={csec}")
    k = 0
    while co is not None:
        cb = struct.unpack_from("<Q", data, co + k*8)[0]
        if cb == 0:
            break
        cbrva = cb - IMAGE_BASE
        cbo, _ = pe.rva2off(cbrva)
        bts = data[cbo:cbo+24].hex(' ') if cbo else "?"
        print(f"   TLS callback[{k}] VA=0x{cb:X} rva=0x{cbrva:X} bytes: {bts}")
        k += 1
    if k == 0:
        print("   (callback array empty)")

# ---- Export dir ----
exp_rva, exp_size = pe.dir(0)
print(f"\n== Export dir rva=0x{exp_rva:X} size=0x{exp_size:X} ==")
eo, esec = pe.rva2off(exp_rva)
if eo:
    flags, tstamp, mj, mn, name_rva, base, nfuncs, nnames, af, an, ao = struct.unpack_from("<IIHHIIIIIII", data, eo)
    print(f"   nfuncs={nfuncs} nnames={nnames} base={base} (raw={data[eo:eo+40].hex(' ')})")
    if 0 < nnames < 100 and an:
        an_off, _ = pe.rva2off(an)
        ao_off, _ = pe.rva2off(ao) if ao else (None, None)
        af_off, _ = pe.rva2off(af)
        for k in range(nnames):
            nrva = struct.unpack_from("<I", data, an_off + k*4)[0]
            noff, _ = pe.rva2off(nrva)
            nm = data[noff:data.find(b"\x00", noff)].decode("ascii", "replace")
            oi = struct.unpack_from("<H", data, ao_off + k*2)[0] if ao_off else k
            frva = struct.unpack_from("<I", data, af_off + oi*4)[0] if af_off else 0
            print(f"   export '{nm}' ord={base+oi} rva=0x{frva:X}")

# ---- Debug dir ----
dbg_rva, dbg_size = pe.dir(6)
do_, _ = pe.rva2off(dbg_rva)
print(f"\n== Debug dir rva=0x{dbg_rva:X} size=0x{dbg_size:X} file=0x{do_:08X} ==")
n = dbg_size // 28
for k in range(n):
    chars, tstamp, mj, mn, dtype, szdata, addr, ptr = struct.unpack_from("<IIHHIIII", data, do_ + k*28)
    s = data[ptr:ptr+min(szdata, 120)]
    print(f"   [{k}] type={dtype} size={szdata} raw={s[:88]!r}")

# ---- LoadConfig GuardFlags (any CF guard added?) ----
lc_rva, lc_size = pe.dir(10)
lo, _ = pe.rva2off(lc_rva)
if lo:
    size_lc, tstamp_lc, gp = struct.unpack_from("<IIQ", data, lo)[:3] if False else (0,0,0)
    # just read GuardFlags at +0x28
    gflags = struct.unpack_from("<I", data, lo + 0x28)[0]
    print(f"\n== LoadConfig rva=0x{lc_rva:X} GuardFlags=0x{gflags:08X} ==")

# ================= UPX NRV2B unpack of gdk_patch.dll =================
print("\n================ gdk_patch.dll UPX unpack ================")
with open(GP, "rb") as f:
    g = f.read()
h = g.find(b"UPX!")
# l_info: 'UPX!' + version + format + method + level (8 bytes) then u_adler,c_adler,u_len,c_len,u_file_size,filter,filter_cto,n_mru,header_checksum (20 bytes)
ver, fmt, method, level = g[h+4], g[h+5], g[h+6], g[h+7]
u_adler, c_adler, u_len, c_len, u_file_size = struct.unpack_from("<IIIII", g, h+8)
filter_, filter_cto, n_mru, hchk = struct.unpack_from("<HBBHI", g, h+28) if False else (0,0,0,0)
filter_, filter_cto = g[h+28], g[h+29]
print(f"version={ver} format={fmt} method={method} level={level} u_len=0x{u_len:X} c_len=0x{c_len:X} u_file_size=0x{u_file_size:X} filter={filter_} cto=0x{filter_cto:02X}")
# p_info header usually right before l_info: progid, filesize, blocksize
# compressed blocks: for PE, single block starting at UPX1 raw data? The block header: sz_unc, sz_cmp, method/filter...
# For PE format the first block header is at start of UPX1 section data:
# layout: [p_info? no] For PE, UPX1 contains: <block header: u32 sz_unc, u32 sz_cmp, u08 method, u08 filter> then compressed data
# Let's find the block: UPX1 raw ptr = 0x400. Actually with the stub, data starts at file 0x400.
# PE32+ packed: at 0x400 there is typically the compressed stream with block header
bh = 0x400
sz_unc, sz_cmp = struct.unpack_from("<II", g, bh)
mth = g[bh+8]; flt = g[bh+9]
print(f"block@0x400: sz_unc=0x{sz_unc:X} sz_cmp=0x{sz_cmp:X} method={mth} filter={flt}")
# For exe/dll with UPX, usually there are two blocks: one for UPX0+UPX1 area, plus header rebuild info at end.
# We'll decompress method 2 (NRV2B_LE32) if that matches; else try to locate 'UPX!' final l_info for adding:
# simpler: decompress the single main block.

def nrv2b_decompress(src, dst_len):
    """NRV2B_LE32 decompressor (standard UPX)."""
    src_i = 0
    dst = bytearray()
    bc = 0  # bit buffer counter
    ilen = 0
    last_m_off = 0

    def getbit():
        nonlocal bc, ilen
        # LE32 variant: 32-bit little-endian bit buffer
        nonlocal_buffer = 0
        return 0

    # implement classic ucl_nrv2b_le32
    state = {"bb": 0, "bc": 0, "ip": 0}

    def getbit_le32():
        if state["bc"] == 0:
            state["bb"] = struct.unpack_from("<I", src, state["ip"])[0]
            state["ip"] += 4
            state["bc"] = 32
        state["bc"] -= 1
        bit = (state["bb"] >> state["bc"]) & 1
        return bit

    try:
        while True:
            while getbit_le32():
                if len(dst) >= dst_len:
                    return bytes(dst), state["ip"]
                dst.append(src[state["ip"]]); state["ip"] += 1
                if len(dst) >= dst_len:
                    return bytes(dst), state["ip"]
            m_off = 1
            while True:
                m_off = m_off*2 + getbit_le32()
                if getbit_le32():
                    break
                m_off = (m_off - 1)*2 + getbit_le32()
            if m_off == 2:
                m_off = last_m_off
                m_len = getbit_le32()
            else:
                m_off = (m_off - 3)*256 + src[state["ip"]]
                state["ip"] += 1
                if m_off == 0xFFFFFFFF:
                    break
                last_m_off = m_off + 1
                m_len = (m_off ^ 0xFFFFFFFF) & 1
                m_off = last_m_off if m_len == 0 else last_m_off
                # standard: m_len = (m_off-1)&1 style; use canonical impl below
                m_off = last_m_off
                m_len = 1 + ((last_m_off ^ 0xFFFFFFFF) & 1)
            if m_len == 0 and m_off == 1:  # EOF marker guard
                pass
            if m_off == 2:
                m_off = last_m_off
            else:
                last_m_off = m_off
            m_len += 1
            if m_off > len(dst):
                raise ValueError(f"bad offset m_off={m_off} dstlen={len(dst)} ip={state['ip']}")
            for _ in range(m_len):
                dst.append(dst[-m_off])
                if len(dst) >= dst_len:
                    return bytes(dst), state["ip"]
    except (IndexError, struct.error) as ex:
        print(f"   decompress stopped: {ex} at dst=0x{len(dst):X} ip=0x{state['ip']:X}")
    return bytes(dst), state["ip"]

# UPX PE: compressed data begins at UPX1 file offset 0x400? The stub is at 0x400... Actually for PE32+, stub code is in UPX1 too.
# Standard layout: first section UPX0 (vsize 0x8000) holds unpacked image; UPX1 (vsize 0x4000) holds stub + compressed.
# Compressed stream starts at the entry point? Entry = ? read it:
ep = struct.unpack_from("<I", g, struct.unpack_from("<I", g, 0x3C)[0] + 24 + 16)[0]
print(f"gdk_patch EP rva=0x{ep:X}")
# UPX puts a jump at entry to the stub; the compressed data usually begins right after the import stub, at the
# position marked by the 'UPX!' l_info we found? No - l_info is at end of stub. The block header (sz_unc,sz_cmp,method,filter)
# follows the stub. We found l_info at 0x3E0 (inside first 0x400). So compressed block header likely at 0x400 exactly.
sz_unc, sz_cmp, mth, flt = struct.unpack_from("<IIBB", g, 0x400)
print(f"block@0x400: sz_unc=0x{sz_unc:X} sz_cmp=0x{sz_cmp:X} method={mth} filter={flt}")
if mth == 2:
    comp = g[0x40C:0x40C+sz_cmp]
    out, ip = nrv2b_decompress(comp, sz_unc)
    print(f"decompressed {len(out):,} bytes (consumed 0x{ip:X})")
    with open(r"E:\mcb\Fiber\docs\gdk_patch_unpacked.bin", "wb") as f:
        f.write(out)
    # dump printable strings
    print("-- strings in unpacked gdk_patch (>=5 chars) --")
    for m in re.finditer(rb"[\x20-\x7E]{5,}", out):
        s = m.group().decode("ascii")
        print(f"  0x{m.start():05X}: {s[:150]}")
else:
    print(f"  method={mth} not NRV2B; not decompressing here")
