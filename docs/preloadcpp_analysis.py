#!/usr/bin/env python3
"""preloadcpp_analysis.py - full static analysis of PreloadCpp.dll (and gdk_patch stub info)."""
import struct
import re

ROOT = r"E:\mcb\bedrock_versions\1.26.3301"
PC = ROOT + r"\PreloadCpp.dll"
GP = ROOT + r"\preload\gdk_patch.dll"

def load(path):
    with open(path, "rb") as f:
        return f.read()

class PE:
    def __init__(self, data):
        self.data = data
        e = struct.unpack_from("<I", data, 0x3C)[0]
        self.e = e
        self.nsec = struct.unpack_from("<H", data, e+6)[0]
        opt = e + 24
        self.opt = opt
        self.is64 = struct.unpack_from("<H", data, opt)[0] == 0x20B
        self.sections = []
        off = opt + (0xF0 if self.is64 else 0xE0)
        for i in range(self.nsec):
            name = data[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off+8)
            chars = struct.unpack_from("<I", data, off+36)[0]
            self.sections.append((name, vaddr, vsize, rptr, rsize, chars))
            off += 40

    def rva2off(self, r):
        for n, va, vs, rp, rs, ch in self.sections:
            if va <= r < va + max(vs, rs):
                return rp + (r - va), n
        return None, None

    def dir(self, i):
        return struct.unpack_from("<II", self.data, self.opt + 0x60 + i*8)

    def ascii_strings(self, minlen=5):
        return [(m.start(), m.group().decode("ascii")) for m in re.finditer(rb"[\x20-\x7E]{%d,}" % minlen, self.data)]

    def utf16_strings(self, minlen=5):
        pat = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % minlen)
        return [(m.start(), m.group().decode("utf-16le")) for m in pat.finditer(self.data)]


def dump_pe(path, label):
    data = load(path)
    pe = PE(data)
    print(f"===== {label}: {path} ({len(data):,} bytes) =====")
    ts = struct.unpack_from("<I", data, pe.e+8)[0]
    print(f"timestamp=0x{ts:X}  subsystem={struct.unpack_from('<H', data, pe.opt+68)[0]}  dllchars=0x{struct.unpack_from('<H', data, pe.opt+70)[0]:X}")
    for n, va, vs, rp, rs, ch in pe.sections:
        print(f"  sec {n:8s} rva=0x{va:06X} vsize=0x{vs:06X} file=0x{rp:06X} rsize=0x{rs:06X} chars=0x{ch:08X}")
    # exports
    erva, esize = pe.dir(0)
    print(f"-- exports (dir rva=0x{erva:X} size=0x{esize:X}) --")
    if erva:
        eo, esec = pe.rva2off(erva)
        sane = False
        if eo is not None:
            flags, tstamp, major, minor, name_rva, ordinal_base, nfuncs, nnames, af_rva, an_rva, ao_rva = struct.unpack_from("<IIHHIIIIIII", data, eo)
            sane = (nfuncs < 100000 and nnames < 100000 and (an_rva or af_rva))
        if not sane:
            print(f"   export directory present but CORRUPT/WIPED (raw first 44 bytes: {data[eo:eo+44].hex(' ') if eo else 'unmapped'})")
            print("   -> export dir RVA points into non-export data; treat as no usable exports")
            erva = 0
    if erva:
        eo, _ = pe.rva2off(erva)
        if eo is not None:
            flags, tstamp, major, minor, name_rva, ordinal_base, nfuncs, nnames, af_rva, an_rva, ao_rva = struct.unpack_from("<IIHHIIIIIII", data, eo)
            no, _ = pe.rva2off(name_rva)
            dllname = data[no:data.find(b"\x00", no)].decode("ascii", "replace") if no else "?"
            print(f"   dll name='{dllname}' nfuncs={nfuncs} nnames={nnames} ordinal_base={ordinal_base}")
            if an_rva:
                an_off, _ = pe.rva2off(an_rva)
                af_off, _ = pe.rva2off(af_rva)
                ao_off, _ = pe.rva2off(ao_rva) if ao_rva else (None, None)
                for i in range(nnames):
                    nrva = struct.unpack_from("<I", data, an_off + i*4)[0]
                    noff, _ = pe.rva2off(nrva)
                    nm = data[noff:data.find(b"\x00", noff)].decode("ascii", "replace") if noff else "?"
                    ord_idx = struct.unpack_from("<H", data, ao_off + i*2)[0] if ao_off else i
                    frva = struct.unpack_from("<I", data, af_off + ord_idx*4)[0]
                    print(f"   export '{nm}' ordinal={ordinal_base+ord_idx} rva=0x{frva:X}")
            else:
                # export by ordinal only
                af_off, _ = pe.rva2off(af_rva)
                for i in range(min(nfuncs, 32)):
                    frva = struct.unpack_from("<I", data, af_off + i*4)[0]
                    print(f"   export ord={ordinal_base+i} rva=0x{frva:X}")
        else:
            print("   export dir RVA not mapped!")
    else:
        print("   none")
    # imports
    irva, isize = pe.dir(1)
    print(f"-- imports (dir rva=0x{irva:X}) --")
    if irva:
        io, _ = pe.rva2off(irva)
        i = 0
        while io is not None:
            oft, tstamp, fwd, name_rva, iat = struct.unpack_from("<IIIII", data, io + i*20)
            if not name_rva:
                break
            no, _ = pe.rva2off(name_rva)
            dll = data[no:data.find(b"\x00", no)].decode("ascii", "replace") if no else "?"
            thunk = oft or iat
            to, _ = pe.rva2off(thunk)
            funcs = []
            k = 0
            while to is not None:
                val = struct.unpack_from("<Q", data, to + k*8)[0]
                if val == 0:
                    break
                if val & (1 << 63):
                    funcs.append(f"ord{val & 0xFFFF}")
                else:
                    ho, _ = pe.rva2off(val & 0x7FFFFFFF)
                    if ho:
                        funcs.append(data[ho+2:data.find(b"\x00", ho+2)].decode("ascii", "replace"))
                k += 1
            print(f"   {dll}: {', '.join(funcs) if funcs else '(empty)'}")
            i += 1
    else:
        print("   none (import directory zeroed)")
    # delay imports
    drva, _ = pe.dir(13)
    print(f"-- delay imports (dir rva=0x{drva:X}) --")
    if drva:
        do, _ = pe.rva2off(drva)
        i = 0
        while do is not None:
            attrs, name_rva, mod, intt, iat, b, u, f = struct.unpack_from("<IIIIIIII", data, do + i*32)
            if not name_rva:
                break
            no, _ = pe.rva2off(name_rva)
            dll = data[no:data.find(b"\x00", no)].decode("ascii", "replace") if no else "?"
            print(f"   {dll}")
            i += 1
    else:
        print("   none")
    # TLS callbacks
    trva, _ = pe.dir(9)
    if trva:
        to_, _ = pe.rva2off(trva)
        if to_ is not None:
            _, _, _, cb = struct.unpack_from("<QQQQ", data, to_)
            print(f"-- TLS callbacks VA=0x{cb:X} --")
    print()

dump_pe(PC, "PreloadCpp.dll")
dump_pe(GP, "gdk_patch.dll (packed)")

# ---- PreloadCpp strings ----
data = load(PC)
pe = PE(data)
print("===== PreloadCpp.dll ascii strings >=5 chars =====")
for off, s in pe.ascii_strings(5):
    rva, sec = 0, "?"
    for n, va, vs, rp, rs, ch in pe.sections:
        if rp <= off < rp + rs:
            rva = va + (off - rp); sec = n
    print(f"  f=0x{off:05X} rva=0x{rva:05X} [{sec}] {s[:160]}")

print()
print("===== PreloadCpp.dll utf16 strings >=4 chars =====")
for off, s in pe.utf16_strings(4):
    print(f"  f=0x{off:05X} {s[:160]}")

# focus greps
print()
print("===== focused greps in PreloadCpp.dll =====")
for pat in [b"preload", b"Preload", b"PRELOAD", b"gdk_patch", b"*.dll", b".dll", b"LoadLibrary", b"FindFirstFile", b"GetProcAddress", b"%s.dll", b"\\%s"]:
    hits = [m.start() for m in re.finditer(re.escape(pat), data)]
    print(f"  {pat!r}: {len(hits)} hits -> {[hex(h) for h in hits[:20]]}")

# ---- gdk_patch UPX info ----
g = load(GP)
print()
print("===== gdk_patch.dll UPX header info =====")
ups = [m.start() for m in re.finditer(b"UPX!", g)]
print(f"  'UPX!' magic occurrences: {[hex(h) for h in ups]}")
for h in ups:
    print(f"   around 0x{h:X}: {g[h-12:h+20].hex(' ')}  |{''.join(chr(c) if 32<=c<127 else '.' for c in g[h-12:h+20])}|")
# UPX l_info struct: magic UPX!, version, format, method, level, u_adler, c_adler, u_len, c_len, u_file_size, filter, filter_cto, n_mru/unused, header_checksum
h = ups[-1] if ups else None
if h:
    ver, fmt, method, level = g[h+4], g[h+5], g[h+6], g[h+7]
    u_adler, c_adler, u_len, c_len, u_file_size = struct.unpack_from("<IIIII", g, h+8)
    print(f"  version={ver} format={fmt} method={method} level={level} u_len=0x{u_len:X} c_len=0x{c_len:X} u_file_size=0x{u_file_size:X}")
