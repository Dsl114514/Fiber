#!/usr/bin/env python3
"""preload_scan.py - scan Minecraft.Windows.exe for 'preload'/'gdk_patch' strings,
context, and rip-relative code xrefs. stdlib only. Read-only on target."""
import re
import struct
import sys

EXE = r"E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe"
OUT = r"E:\mcb\Fiber\docs\preload_scan_results.txt"
CONTEXT = 200  # bytes each side


class PE:
    def __init__(self, data):
        self.data = data
        e = struct.unpack_from("<I", data, 0x3C)[0]
        assert data[e:e+4] == b"PE\x00\x00"
        self.nsec = struct.unpack_from("<H", data, e+6)[0]
        opt = e + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        self.is64 = magic == 0x20B
        self.sections = []
        off = opt + (0xF0 if self.is64 else 0xE0)
        for i in range(self.nsec):
            name = data[off:off+8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off+8)
            self.sections.append((name, vaddr, vsize, rptr, rsize))
            off += 40

    def off_to_rva(self, o):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            if rptr <= o < rptr + rsize:
                return vaddr + (o - rptr), name
        return None, None

    def rva_to_off(self, r):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            if vaddr <= r < vaddr + max(vsize, rsize):
                return rptr + (r - vaddr), name
        return None, None


def printable(b):
    out = []
    for c in b:
        out.append(chr(c) if 32 <= c < 127 else ".")
    return "".join(out)


def render_utf16(b):
    """render a byte range as utf-16le-ish for readability"""
    s = b.decode("utf-16le", "replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in s)


def main():
    print(f"reading {EXE} ...")
    with open(EXE, "rb") as f:
        data = f.read()
    print(f"size = {len(data):,}")
    pe = PE(data)

    with open(OUT, "w", encoding="utf-8") as log:
        def P(s=""):
            print(s)
            log.write(s + "\n")

        P(f"# preload_scan results  ({EXE}, {len(data):,} bytes)")
        P("# sections:")
        for name, vaddr, vsize, rptr, rsize in pe.sections:
            P(f"#   {name:8s} rva=0x{vaddr:08X} vsize=0x{vsize:08X} file=0x{rptr:08X} rsize=0x{rsize:08X}")
        P()

        needles = {
            "ascii:preload": b"preload",
            "ascii:Preload": b"Preload",
            "ascii:gdk_patch": b"gdk_patch",
        }
        for label, needle in needles.items():
            for enc, tag in ((needle, "A"), (needle.decode().encode("utf-16le"), "W")):
                hits = [m.start() for m in re.finditer(re.escape(enc), data)]
                P(f"== {label} [{tag}] : {len(hits)} hits ==")
                for h in hits:
                    rva, sec = pe.off_to_rva(h)
                    lo, hi = max(0, h - CONTEXT), min(len(data), h + len(enc) + CONTEXT)
                    ctx = data[lo:hi]
                    P(f"-- file=0x{h:08X} rva={('0x%08X' % rva) if rva else '?'} sec={sec}")
                    P(f"   ctx_ascii: {printable(ctx)}")
                    if tag == "W":
                        P(f"   ctx_u16  : {render_utf16(ctx)}")
                P()

        # ---- imports / delayed imports scan for interesting APIs ----
        P("== interesting API name scan (import + delay import tables, raw string search) ==")
        apis = [b"FindFirstFile", b"FindNextFile", b"LoadLibrary", b"GetFileAttributes",
                b"CreateFile", b"LdrLoadDll", b"LoadPackagedLibrary"]
        for api in apis:
            hits = [m.start() for m in re.finditer(re.escape(api), data)]
            P(f"  {api.decode()}: {len(hits)} raw occurrences")
            for h in hits[:40]:
                rva, sec = pe.off_to_rva(h)
                end = data.find(b"\x00", h)
                name = printable(data[h:min(end, h+64)])
                P(f"    file=0x{h:08X} rva={('0x%08X' % rva) if rva else '?'} sec={sec}  name='{name}'")
        P()

    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
