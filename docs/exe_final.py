#!/usr/bin/env python3
"""exe_final.py - corrected PE32+ data directory analysis (DD base = opt+0x70).
Walks the .addImp import directory, finds PreloadCpp.dll descriptor + IAT,
scans .text for FF15 call sites, dumps EP + TLS callbacks, and fixes
PreloadCpp.dll export/import parse."""
import struct
import re

EXE = r"E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe"
PC = r"E:\mcb\bedrock_versions\1.26.3301\PreloadCpp.dll"

class PE:
    def __init__(self, data):
        self.data = data
        e = struct.unpack_from("<I", data, 0x3C)[0]
        self.e = e
        opt = e + 24
        self.opt = opt
        self.magic = struct.unpack_from("<H", data, opt)[0]
        assert self.magic == 0x20B, "expect PE32+"
        self.ddbase = opt + 0x70          # PE32+ DataDirectory
        self.nsec = struct.unpack_from("<H", data, e+6)[0]
        self.sections = []
        off = opt + 0xF0
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

DIRN = ["Export","Import","Resource","Exception","Security","BaseReloc","Debug",
        "Architecture","GlobalPtr","TLS","LoadConfig","BoundImport","IAT",
        "DelayImport","COM","Reserved"]

print("################ MAIN EXE ################")
with open(EXE, "rb") as f:
    data = f.read()
pe = PE(data)
n_ras = struct.unpack_from("<Q", data, pe.opt + 0x6C)[0]
print(f"NumberOfRvaAndSizes (at opt+0x6C) = 0x{n_ras:X}")
print("== corrected data directories ==")
for i in range(16):
    rva, size = pe.dir(i)
    if rva or size:
        # Security dir is a file offset, not RVA
        if i == 4:
            fo = rva
            print(f"  [{i:2d}] {DIRN[i]:12s} file_off=0x{rva:08X} size=0x{size:08X} (security uses file offset)")
            if fo + 24 <= len(data):
                hdr = data[fo:fo+8]
                ln, rev, ctype = struct.unpack_from("<IHH", data, fo)
                print(f"        WIN_CERTIFICATE? dwLength=0x{ln:X} rev=0x{rev:X} type=0x{ctype:X}  raw8={hdr.hex(' ')}")
        else:
            fo, sn = pe.rva2off(rva)
            print(f"  [{i:2d}] {DIRN[i]:12s} rva=0x{rva:08X} size=0x{size:08X} file={('0x%08X'%fo) if fo else '-':>10s} sec={sn}")

# ---- import directory walk ----
imp_rva, imp_size = pe.dir(1)
print(f"\n== import directory rva=0x{imp_rva:X} size=0x{imp_size:X} ==")
io, isec = pe.rva2off(imp_rva)
print(f"  file=0x{io:08X} sec={isec}")
dlls = []
preload_desc = None
i = 0
while True:
    oft, ts, fwd, name_rva, iat = struct.unpack_from("<IIIII", data, io + i*20)
    if not name_rva and not oft and not iat:
        break
    no, _ = pe.rva2off(name_rva)
    end = data.find(b"\x00", no, no+128)
    nm = data[no:end].decode("ascii", "replace") if no and end > no else f"??(rva=0x{name_rva:08X})"
    dlls.append((i, nm, oft, iat, io + i*20))
    if "reloadcpp" in nm.lower() or "reload" in nm.lower():
        preload_desc = (i, oft, name_rva, iat, io + i*20)
    i += 1
print(f"  total descriptors: {len(dlls)}")
for idx, nm, oft, iat, doff in dlls[:6]:
    print(f"   [{idx:2d}] file=0x{doff:08X} {nm}  OFT=0x{oft:08X} IAT=0x{iat:08X}")
print("   ...")
for idx, nm, oft, iat, doff in dlls[-6:]:
    print(f"   [{idx:2d}] file=0x{doff:08X} {nm}  OFT=0x{oft:08X} IAT=0x{iat:08X}")

# PreloadCpp descriptor detail
if preload_desc:
    idx, oft, name_rva, iat, doff = preload_desc
    print(f"\n== PreloadCpp.dll descriptor @ file=0x{doff:08X} (index {idx}, LAST before terminator) ==")
    # dump raw descriptor bytes + name area + thunk/IAT area
    print(f"  raw desc: {data[doff:doff+20].hex(' ')}")
    no, _ = pe.rva2off(name_rva)
    print(f"  name rva=0x{name_rva:08X} file=0x{no:08X}: {data[no:no+48]!r}")
    to, tsec = pe.rva2off(iat)
    print(f"  IAT rva=0x{iat:08X} file=0x{to:08X} sec={tsec}")
    k = 0
    while True:
        val = struct.unpack_from("<Q", data, to + k*8)[0]
        if val == 0:
            break
        if val & (1 << 63):
            print(f"    IAT[{k}] ordinal {val & 0xFFFF}")
        else:
            ho, _ = pe.rva2off(val & 0x7FFFFFFF)
            hint = struct.unpack_from("<H", data, ho)[0]
            fn = data[ho+2:data.find(b"\x00", ho+2)].decode("ascii", "replace")
            print(f"    IAT[{k}] -> IMAGE_IMPORT_BY_NAME rva=0x{val & 0x7FFFFFFF:X} hint={hint} name='{fn}'")
        k += 1
    iat_rva = iat
    # scan .text for FF15 / FF25 / mov rip-rel refs to the IAT slot(s)
    tname, tva, tvs, trp, trs = [s for s in pe.sections if s[0] == ".text"][0]
    buf = data[trp:trp+trs]
    print(f"  -- .text refs to IAT rva 0x{iat_rva:X} --")
    found_any = False
    for patlen, pat, relpos in ((6, b"\xFF\x15", 2), (6, b"\xFF\x25", 2), (7, b"\x48\x8B\x05", 3), (7, b"\x48\x8D\x0D", 3)):
        j = 0
        while True:
            j = buf.find(pat, j)
            if j < 0 or j + patlen > len(buf):
                break
            rel = struct.unpack_from("<i", buf, j + relpos)[0]
            site = tva + j
            if site + patlen + rel == iat_rva:
                print(f"    {pat.hex(' ')}... at rva=0x{site:08X} file=0x{trp+j:08X} ({'call/jmp [rip+..]' if pat[0]==0xFF else 'mov/lea [rip+..]'})")
                found_any = True
            j += 1
    if not found_any:
        print("    (none found)")

# ---- entry point bytes ----
ep_rva = struct.unpack_from("<I", data, pe.opt + 16)[0]
ep_off, ep_sec = pe.rva2off(ep_rva)
print(f"\n== entry point rva=0x{ep_rva:08X} file=0x{ep_off:08X} sec={ep_sec} ==")
chunk = data[ep_off:ep_off+64]
print(f"  bytes: {chunk.hex(' ')}")
# try to find what it does: naive scan for FF15 targets within first 64 bytes
j = 0
while j < 58:
    if chunk[j:j+2] == b"\xFF\x15":
        rel = struct.unpack_from("<i", chunk, j+2)[0]
        tgt = ep_rva + j + 6 + rel
        print(f"    EP+0x{j:02X}: call [rip+0x{rel:X}] -> rva 0x{tgt:08X}")
    if chunk[j:j+2] == b"\xE9":
        rel = struct.unpack_from("<i", chunk, j+2)[0]
        tgt = ep_rva + j + 5 + rel
        print(f"    EP+0x{j:02X}: jmp 0x{tgt:08X}")
    j += 1

# ---- TLS ----
tls_rva, tls_size = pe.dir(9)
if tls_rva:
    to_, _ = pe.rva2off(tls_rva)
    start, end, idxva, cbva = struct.unpack_from("<QQQQ", data, to_)
    print(f"\n== TLS dir rva=0x{tls_rva:08X}: callbacks array VA=0x{cbva:X} ==")
    if cbva:
        co, _ = pe.rva2off(cbva & 0xFFFFFFFFFFFF)
        if co:
            k = 0
            while True:
                cb = struct.unpack_from("<Q", data, co + k*8)[0]
                if cb == 0:
                    break
                print(f"    TLS callback[{k}] VA=0x{cb:X}")
                k += 1

# ---- debug directory (PDB path) ----
dbg_rva, dbg_size = pe.dir(6)
if dbg_rva:
    do_, _ = pe.rva2off(dbg_rva)
    print(f"\n== debug directory rva=0x{dbg_rva:08X} entries ==")
    n = dbg_size // 28
    for k in range(min(n, 12)):
        chars, tstamp, mj, mn, dtype, szdata, addr, ptr = struct.unpack_from("<IIHHIIII", data, do_ + k*28)
        s = data[ptr:ptr+min(szdata, 120)]
        txt = s.decode("utf-8", "replace") if dtype in (2,) else s[:40].hex(' ')
        print(f"    [{k}] type={dtype} size={szdata} '{txt}'" if dtype == 2 else f"    [{k}] type={dtype} size={szdata} data={txt}")

# ---- export dir of main exe ----
exp_rva, exp_size = pe.dir(0)
if exp_rva:
    eo, _ = pe.rva2off(exp_rva)
    flags, tstamp, mj, mn, name_rva, base, nfuncs, nnames, af, an, ao = struct.unpack_from("<IIHHIIIIIII", data, eo)
    print(f"\n== main exe export dir rva=0x{exp_rva:X}: nfuncs={nfuncs} nnames={nnames} ==")
    if 0 < nnames < 1000 and an:
        an_off, _ = pe.rva2off(an)
        ao_off, _ = pe.rva2off(ao) if ao else (None, None)
        af_off, _ = pe.rva2off(af)
        for k in range(nnames):
            nrva = struct.unpack_from("<I", data, an_off + k*4)[0]
            noff, _ = pe.rva2off(nrva)
            nm = data[noff:data.find(b"\x00", noff)].decode("ascii", "replace")
            oi = struct.unpack_from("<H", data, ao_off + k*2)[0] if ao_off else k
            frva = struct.unpack_from("<I", data, af_off + oi*4)[0] if af_off else 0
            print(f"    '{nm}' ord={base+oi} rva=0x{frva:X}")
else:
    print("\n== main exe has NO export directory ==")

print()
print("################ PreloadCpp.dll (corrected) ################")
with open(PC, "rb") as f:
    pdata = f.read()
ppe = PE(pdata)
n_ras2 = struct.unpack_from("<Q", pdata, ppe.opt + 0x6C)[0]
print(f"NumberOfRvaAndSizes = 0x{n_ras2:X}")
for i in range(16):
    rva, size = ppe.dir(i)
    if rva or size:
        fo, sn = ppe.rva2off(rva)
        print(f"  [{i:2d}] {DIRN[i]:12s} rva=0x{rva:06X} size=0x{size:06X} file={('0x%06X'%fo) if fo else '-'} sec={sn}")

exp_rva, exp_size = ppe.dir(0)
print(f"\n-- PreloadCpp exports (dir rva=0x{exp_rva:X} size=0x{exp_size:X}) --")
if exp_rva:
    eo, _ = ppe.rva2off(exp_rva)
    if eo:
        flags, tstamp, mj, mn, name_rva, base, nfuncs, nnames, af, an, ao = struct.unpack_from("<IIHHIIIIIII", pdata, eo)
        no, _ = ppe.rva2off(name_rva)
        dllname = pdata[no:pdata.find(b"\x00", no)].decode("ascii", "replace")
        print(f"   dll='{dllname}' nfuncs={nfuncs} nnames={nnames} base={base}")
        an_off, _ = ppe.rva2off(an)
        ao_off, _ = ppe.rva2off(ao)
        af_off, _ = ppe.rva2off(af)
        for k in range(nnames):
            nrva = struct.unpack_from("<I", pdata, an_off + k*4)[0]
            noff, _ = ppe.rva2off(nrva)
            nm = pdata[noff:pdata.find(b"\x00", noff)].decode("ascii", "replace")
            oi = struct.unpack_from("<H", pdata, ao_off + k*2)[0] if ao_off else k
            frva = struct.unpack_from("<I", pdata, af_off + oi*4)[0] if af_off else 0
            fo2, _ = ppe.rva2off(frva)
            first = pdata[fo2:fo2+16].hex(' ') if fo2 else "-"
            print(f"   '{nm}' ord={base+oi} rva=0x{frva:X} file=0x{fo2:X} bytes={first}")

imp_rva, imp_size = ppe.dir(1)
print(f"\n-- PreloadCpp imports (dir rva=0x{imp_rva:X}) --")
if imp_rva:
    io2, _ = ppe.rva2off(imp_rva)
    k = 0
    while True:
        oft, ts, fwd, name_rva, iat = struct.unpack_from("<IIIII", pdata, io2 + k*20)
        if not name_rva:
            break
        no, _ = ppe.rva2off(name_rva)
        dll = pdata[no:pdata.find(b"\x00", no)].decode("ascii", "replace")
        thunk = oft or iat
        to2, _ = ppe.rva2off(thunk)
        funcs = []
        m = 0
        while to2 is not None:
            val = struct.unpack_from("<Q", pdata, to2 + m*8)[0]
            if val == 0:
                break
            if val & (1 << 63):
                funcs.append(f"ord{val & 0xFFFF}")
            else:
                ho, _ = ppe.rva2off(val & 0x7FFFFFFF)
                if ho:
                    funcs.append(pdata[ho+2:pdata.find(b"\x00", ho+2)].decode("ascii", "replace"))
            m += 1
        print(f"   {dll} ({len(funcs)}): {', '.join(funcs[:14])}{' ...' if len(funcs) > 14 else ''}")
        k += 1

# export-name search: standalone 'Load'
print("\n-- search for export name 'Load' in PreloadCpp.dll --")
for m in re.finditer(rb"\x00Load\x00", pdata):
    o = m.start() + 1
    rva, sec = ppe.off2rva(o)
    print(f"   found 'Load' at file=0x{o:05X} rva=0x{rva:X} sec={sec}  ctx={pdata[o-24:o+16]!r}")
