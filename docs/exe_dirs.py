#!/usr/bin/env python3
"""exe_dirs.py - dump main exe data directories, find which section the import
directory lives in, locate PreloadCpp.dll import descriptor + IAT, TLS callbacks,
and the .addImp layout around the PreloadCpp.dll string. stdlib only, read-only."""
import struct

EXE = r"E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe"

with open(EXE, "rb") as f:
    data = f.read()

e = struct.unpack_from("<I", data, 0x3C)[0]
machine, nsec = struct.unpack_from("<HH", data, e + 4)
opt = e + 24
magic = struct.unpack_from("<H", data, opt)[0]
print(f"machine=0x{machine:X} nsec={nsec} magic=0x{magic:X}")
# optional header fields
print(f"AddressOfEntryPoint = 0x{struct.unpack_from('<I', data, opt+16)[0]:08X}")
print(f"ImageBase           = 0x{struct.unpack_from('<Q', data, opt+24)[0]:X}")
print(f"FileAlignment       = 0x{struct.unpack_from('<I', data, opt+36)[0]:X}")
print(f"SectionAlignment    = 0x{struct.unpack_from('<I', data, opt+32)[0]:X}")
print(f"Characteristics     = 0x{struct.unpack_from('<H', data, e+22)[0]:X}")
ts = struct.unpack_from("<I", data, e+8)[0]
import datetime
print(f"TimeDateStamp       = 0x{ts:X} ({datetime.datetime.utcfromtimestamp(ts) if ts else 0})")

nsec_off = opt + 0xF0
sections = []
off = nsec_off
for i in range(nsec):
    name = data[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
    vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off+8)
    chars = struct.unpack_from("<I", data, off+36)[0]
    sections.append((name, vaddr, vsize, rptr, rsize, chars))
    off += 40

def off2rva(o):
    for n, va, vs, rp, rs, ch in sections:
        if rp <= o < rp + rs:
            return va + (o - rp), n
    return None, None

def rva2off(r):
    for n, va, vs, rp, rs, ch in sections:
        if va <= r < va + max(vs, rs):
            return rp + (r - va), n
    return None, None

print("\n== sections ==")
for n, va, vs, rp, rs, ch in sections:
    print(f"  {n:8s} rva=0x{va:08X} vsize=0x{vs:08X} file=0x{rp:08X} rsize=0x{rs:08X} chars=0x{ch:08X}")

DIRS = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
        "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
        "IAT", "DelayImport", "COM", "Reserved"]
print("\n== data directories ==")
for i in range(16):
    rva, size = struct.unpack_from("<II", data, opt + 0x60 + i*8)
    if rva or size:
        so, sn = rva2off(rva)
        print(f"  [{i:2d}] {DIRS[i]:12s} rva=0x{rva:08X} size=0x{size:08X} file={('0x%08X' % so) if so else '?'} sec={sn}")

# --- import directory walk ---
imp_rva, imp_size = struct.unpack_from("<II", data, opt + 0x60 + 8)
print("\n== import descriptors ==")
o, _ = rva2off(imp_rva)
i = 0
preload_desc = None
while True:
    oft, tstamp, fwd, name_rva, iat = struct.unpack_from("<IIIII", data, o + i*20)
    if not name_rva:
        break
    no, _ = rva2off(name_rva)
    end = data.find(b"\x00", no)
    dll = data[no:end].decode("ascii", "replace")
    if i < 12 or "Preload" in dll or "preload" in dll:
        print(f"  [{i:3d}] {dll:40s} OFT=0x{oft:08X} IAT=0x{iat:08X}")
    if "PreloadCpp" in dll:
        preload_desc = (i, oft, name_rva, iat)
    i += 1
print(f"  ... total {i} import descriptors")

if preload_desc:
    idx, oft, name_rva, iat = preload_desc
    print(f"\n== PreloadCpp.dll import detail ==")
    # walk the OFT / IAT entries
    thunk_rva = oft or iat
    to, _ = rva2off(thunk_rva)
    k = 0
    while True:
        val = struct.unpack_from("<Q", data, to + k*8)[0]
        if val == 0:
            break
        if val & (1 << 63):
            print(f"    thunk[{k}] ordinal {val & 0xFFFF}")
        else:
            ho, _ = rva2off(val & 0x7FFFFFFF)
            end2 = data.find(b"\x00", ho + 2)
            print(f"    thunk[{k}] hint={struct.unpack_from('<H', data, ho)[0]} name='{data[ho+2:end2].decode('ascii','replace')}'")
        k += 1
    io, sn = rva2off(iat)
    print(f"    IAT rva=0x{iat:08X} file=0x{io:08X} sec={sn}")
    # find code refs to IAT: FF 15 <rel32> to iat..iat+8
    target = iat
    hits = []
    for sec_name, va, vs, rp, rs, ch in sections:
        if sec_name != ".text":
            continue
        buf = data[rp:rp+rs]
        j = 0
        while True:
            j = buf.find(b"\xFF\x15", j)
            if j < 0 or j + 6 > len(buf):
                break
            rel = struct.unpack_from("<i", buf, j+2)[0]
            site_rva = va + j
            if site_rva + 6 + rel == target:
                hits.append(site_rva)
            j += 2
    print(f"    .text call [rip] sites targeting IAT: {['0x%08X' % h for h in hits]}")
    # also lea/mov rip-rel referencing IAT slot
    for pat, insn in ((b"\x48\x8B\x05", "mov rax,[rip+"), (b"\x48\x8D\x0D", "lea rcx,[rip+")):
        j = 0
        buf = data[rp:rp+rs]
        cnt = 0
        while True:
            j = buf.find(pat, j)
            if j < 0 or j + 7 > len(buf):
                break
            rel = struct.unpack_from("<i", buf, j+3)[0]
            site_rva = va + j
            if site_rva + 7 + rel == target:
                print(f"    .text {insn}] ref at rva=0x{site_rva:08X}")
                cnt += 1
            j += 1

# --- TLS ---
tls_rva, tls_size = struct.unpack_from("<II", data, opt + 0x60 + 9*8)
if tls_rva:
    print(f"\n== TLS directory rva=0x{tls_rva:08X} ==")
    to, _ = rva2off(tls_rva)
    # PE32+ IMAGE_TLS_DIRECTORY: StartData, EndData, Index, Callbacks, SizeOfZeroFill, Characteristics
    start, endd, index, callbacks = struct.unpack_from("<QQQQ", data, to)
    print(f"  CallbacksVA = 0x{callbacks:X}")
    if callbacks:
        co, _ = rva2off(callbacks - (0 if callbacks < 0x140000000 else 0))
        co, _ = rva2off(callbacks & 0xFFFFFFFF)
        if co is not None:
            k = 0
            while True:
                cb = struct.unpack_from("<Q", data, co + k*8)[0]
                if cb == 0:
                    break
                print(f"    TLS callback[{k}] = 0x{cb:X}")
                k += 1

# --- delay imports ---
del_rva, del_size = struct.unpack_from("<II", data, opt + 0x60 + 13*8)
if del_rva:
    print(f"\n== delay import directory rva=0x{del_rva:08X} size=0x{del_size:X} ==")
    o, _ = rva2off(del_rva)
    i = 0
    while True:
        attrs, name_rva, mod, intt, iat, biat, uiat, flt = struct.unpack_from("<IIIIIIII", data, o + i*32)
        if not name_rva:
            break
        no, _ = rva2off(name_rva)
        end = data.find(b"\x00", no)
        dll = data[no:end].decode("ascii", "replace")
        if i < 8 or "preload" in dll.lower():
            print(f"  [{i:3d}] {dll}")
        i += 1
    print(f"  ... total {i} delay imports")

# --- .addImp layout: strings near the PreloadCpp.dll string ---
print("\n== .addImp neighborhood of 'PreloadCpp.dll' ==")
h = data.find(b"PreloadCpp.dll")
print(f"  string file=0x{h:08X}")
lo, hi = h - 0x100, h + 0x200
chunk = data[lo:hi]
# print as hex+ascii rows
for r in range(0, len(chunk), 32):
    row = chunk[r:r+32]
    fa = lo + r
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
    print(f"  0x{fa:08X}: {row.hex(' ')}  |{asc}|")

# search whole .addImp for import-descriptor-like structures referencing preload folder
print("\n== any 'preload' path-like strings in whole file (b'preload\\\\' and 'preloads') ==")
for needle in (b"preload\\", b"preload/", b"\\preload", b"preloads", b"gdkpatch", b"GdkPatch", b"GDK_PATCH"):
    hits = [m.start() for m in (lambda nd: __import__("re").finditer(__import__("re").escape(nd), data))(needle)]
    print(f"  {needle}: {len(hits)} hits {['0x%X' % x for x in hits[:10]]}")
