#!/usr/bin/env python3
"""peinfo.py - minimal PE forensic tool for Fiber RE workflow (stdlib only)."""
import struct
import sys

MACHINE = {0x8664: "x64", 0x14c: "x86", 0xaa64: "arm64"}


class PE:
    def __init__(self, data: bytes):
        if data[:2] != b"MZ":
            raise ValueError("not a PE (no MZ)")
        self.data = data
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("invalid PE signature")
        self.pe = e_lfanew
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        self.machine = MACHINE.get(machine, hex(machine))
        nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        self.is64 = magic == 0x20B
        self.opt_size = 0xF0 if self.is64 else 0xE0
        self.sections = []
        off = opt + self.opt_size
        for i in range(nsec):
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append((name, vaddr, vsize, rptr, rsize))
            off += 40

    def rva_to_off(self, rva: int):
        for name, vaddr, vsize, rptr, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return rptr + (rva - vaddr)
        return None

    def data_dir_count(self):
        # NumberOfRvaAndSizes is at optional header + 0x70 (PE32) or + 0x88 (PE32+)
        off = self.pe + 24 + (0x88 if self.is64 else 0x70)
        return struct.unpack_from("<I", self.data, off)[0]

    def data_dir(self, idx):
        # DataDirectory starts at optional header + 0x60 (same for PE32 and PE32+)
        off = self.pe + 24 + 0x60 + idx * 8
        n = self.data_dir_count()
        if idx >= n:
            return (0, 0)
        rva, size = struct.unpack_from("<II", self.data, off)
        return (rva, size)


def list_sections(pe):
    print("== sections ==")
    for name, vaddr, vsize, rptr, rsize in pe.sections:
        print(f"  {name:8s} rva=0x{vaddr:08x} vsize=0x{vsize:08x} ptr=0x{rptr:08x} rsize=0x{rsize:08x}")


def list_imports(pe):
    print("== imports ==")
    rva, size = pe.data_dir(1)
    if not rva:
        print("  <none>")
        return
    off = pe.rva_to_off(rva)
    i = 0
    while True:
        entry = off + i * 20
        if entry + 20 > len(pe.data):
            break
        oft, timestamp, fwd, name_rva, iat = struct.unpack_from("<IIIII", pe.data, entry)
        if not name_rva:
            break
        noff = pe.rva_to_off(name_rva)
        end = pe.data.index(b"\x00", noff)
        dll = pe.data[noff:end].decode("ascii", "replace")
        funcs = []
        thunk_rva = iat if iat else oft
        toff = pe.rva_to_off(thunk_rva)
        k = 0
        while toff is not None:
            if pe.is64:
                val = struct.unpack_from("<Q", pe.data, toff + k * 8)[0]
            else:
                val = struct.unpack_from("<I", pe.data, toff + k * 4)[0]
            if val == 0:
                break
            if val & (0x8000000000000000 if pe.is64 else 0x80000000):
                funcs.append(f"ord{val & 0xFFFF}")
            else:
                hint_off = pe.rva_to_off(val & 0x7FFFFFFF)
                if hint_off is not None:
                    end2 = pe.data.index(b"\x00", hint_off + 2)
                    funcs.append(pe.data[hint_off + 2:end2].decode("ascii", "replace"))
                else:
                    funcs.append("?")
            k += 1
        print(f"  {dll} ({len(funcs)})")
        if funcs:
            print(f"      {' '.join(funcs[:12])}{' ...' if len(funcs) > 12 else ''}")
        i += 1


def list_exports(pe):
    print("== exports ==")
    rva, size = pe.data_dir(0)
    if not rva:
        print("  <none>")
        return
    off = pe.rva_to_off(rva)
    nfuncs, nnames = struct.unpack_from("<II", pe.data, off + 0x14)
    names_rva = struct.unpack_from("<I", pe.data, off + 0x20)[0]
    names_off = pe.rva_to_off(names_rva)
    out = []
    for i in range(nnames):
        nrv = struct.unpack_from("<I", pe.data, names_off + i * 4)[0]
        noff = pe.rva_to_off(nrv)
        if noff is None:
            continue
        end = pe.data.index(b"\x00", noff)
        out.append(pe.data[noff:end].decode("ascii", "replace"))
    print(f"  {nfuncs} functions, {nnames} names")
    print(f"  {' '.join(out[:20])}{' ...' if len(out) > 20 else ''}")


def pattern_scan(pe, pat_hex):
    pat = bytes.fromhex(pat_hex.replace(" ", "").replace("?", "00"))
    wild = [c == ord("?") for c in pat_hex.replace(" ", "")]
    hits = []
    data = pe.data
    n = len(pat)
    for i in range(len(data) - n + 1):
        ok = True
        for j in range(n):
            if not wild[j] and data[i + j] != pat[j]:
                ok = False
                break
        if ok:
            hits.append(i)
    print(f"== pattern hits ({len(hits)}) ==")
    for h in hits[:50]:
        rva = None
        for name, vaddr, vsize, rptr, rsize in pe.sections:
            if rptr <= h < rptr + rsize:
                rva = vaddr + (h - rptr)
                break
        print(f"  file=0x{h:08x} rva=0x{rva:08x}" if rva else f"  file=0x{h:08x}")


def main():
    if len(sys.argv) < 2:
        print("usage: peinfo.py <exe> [imports|exports|sections|scan <hex-with-?>]")
        return 1
    with open(sys.argv[1], "rb") as f:
        pe = PE(f.read())
    print(f"machine: {pe.machine}  sections: {len(pe.sections)}")
    cmd = sys.argv[2] if len(sys.argv) > 2 else "sections"
    if cmd == "sections":
        list_sections(pe)
    elif cmd == "imports":
        list_imports(pe)
    elif cmd == "exports":
        list_exports(pe)
    elif sys.argv[2] == "scan":
        if len(sys.argv) < 4:
            print("need pattern hex")
            return 1
        pattern_scan(pe, sys.argv[3])
    return 0


if __name__ == "__main__":
    sys.exit(main())