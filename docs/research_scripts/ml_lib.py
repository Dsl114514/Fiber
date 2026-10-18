#!/usr/bin/env python3
"""ml_lib.py - Foundation library for static analysis of Minecraft.Windows.exe
Read-only. Provides: section map, rva<->file mapping, .pdata function table,
numpy-accelerated xref scanning (E8/E9 direct calls/jmps + rip-relative data refs).
"""
import struct, sys, io
import numpy as np

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

EXE = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'

class PE:
    def __init__(self, path=EXE):
        self.data = open(path, 'rb').read()
        d = self.data
        e = struct.unpack_from('<I', d, 0x3C)[0]
        self.pe_off = e
        self.num_sec = struct.unpack_from('<H', d, e + 6)[0]
        opt_off = e + 24
        magic = struct.unpack_from('<H', d, opt_off)[0]
        assert magic == 0x20B, hex(magic)
        self.image_base = struct.unpack_from('<Q', d, opt_off + 24)[0]
        self.entry_rva = struct.unpack_from('<I', d, opt_off + 16)[0]
        opt_size = struct.unpack_from('<H', d, e + 16)[0]
        sec_off = opt_off + opt_size
        self.sections = []
        for i in range(self.num_sec):
            name = d[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', 'replace')
            vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', d, sec_off+8)
            chara = struct.unpack_from('<I', d, sec_off+32)[0]
            self.sections.append(dict(name=name, vaddr=vaddr, vsize=vsize,
                                      raddr=raddr, rsize=rsize, chara=chara))
            sec_off += 40
        # Data directories
        dd_off = opt_off + 0x60
        self.dd = []
        for i in range(16):
            rva, sz = struct.unpack_from('<II', d, dd_off + i*8)
            self.dd.append((rva, sz))

    def _good_sections(self):
        """Nonstandard header contains 6 fake section entries (vaddr=0 / overlapping).
        Only these 4 are real."""
        return [s for s in self.sections if s['name'] in ('.text', '.rdata', '.data', '.pdata')]

    def off2rva(self, off):
        for s in self._good_sections():
            if s['raddr'] <= off < s['raddr'] + s['rsize']:
                return s['vaddr'] + (off - s['raddr'])
        return -1

    def rva2off(self, rva):
        for s in self._good_sections():
            if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                off = s['raddr'] + (rva - s['vaddr'])
                if off < s['raddr'] + s['rsize']:
                    return off
                return -1
        return -1

    def sec_of_rva(self, rva):
        for s in self._good_sections():
            if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                return s
        return None

    def sec_by_name(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

# ---------------- .pdata function table ----------------

class Pdata:
    def __init__(self, pe):
        s = pe.sec_by_name('.pdata')
        self.pdata = []
        if s is None:
            return
        off = s['raddr']
        n = s['rsize'] // 12
        raw = np.frombuffer(pe.data, dtype=np.uint32, count=n*3, offset=off)
        raw = raw.reshape(n, 3)
        # keep entries sorted by begin; filter zeros
        begins = raw[:, 0].astype(np.uint32)
        order = np.argsort(begins, kind='stable')
        self.entries = raw[order]
        self.begins = self.entries[:, 0].copy()
        self.ends = self.entries[:, 1].copy()
        self.sorted = True

    def find(self, rva):
        """Return (begin, end, unwind) of function containing rva, or None."""
        i = np.searchsorted(self.begins, rva, side='right') - 1
        if i < 0:
            return None
        b, e_ = int(self.begins[i]), int(self.ends[i])
        if b <= rva < e_:
            return (b, e_, int(self.entries[i, 2]))
        return None

    def floor(self, rva):
        """Return (begin,end) of the function whose begin <= rva (last such)."""
        i = np.searchsorted(self.begins, rva, side='right') - 1
        if i < 0:
            return None
        return (int(self.begins[i]), int(self.ends[i]))

# ---------------- Xref scanners (numpy) ----------------

class Scanner:
    def __init__(self, pe):
        self.pe = pe
        t = pe.sec_by_name('.text')
        self.t_off = t['raddr']; self.t_size = t['rsize']
        self.t_rva = t['vaddr']
        self.delta = self.t_rva - self.t_off  # rva = off + delta for .text

    def _chunks(self, chunk=1 << 24):
        off = self.t_off
        end = self.t_off + self.t_size
        while off < end:
            yield off, min(chunk, end - off)
            off += chunk

    def scan_direct(self):
        """Yield arrays: for each direct E8/E9 rel32 in .text: (site_off, target_rva, kind)"""
        d = self.pe.data
        for off, n in self._chunks():
            # need 4 extra bytes lookahead; keep it simple, last 4 bytes of chunk handled next round
            buf = np.frombuffer(d, dtype=np.uint8, count=n, offset=off)
            for opcode in (0xE8, 0xE9):
                pos = np.flatnonzero(buf == opcode)
                if pos.size == 0:
                    continue
                # disp32 at pos+1..pos+4, require pos+5 <= n+... allow reading past chunk via data
                pos_g = pos[pos + 5 <= n]
                if pos_g.size == 0:
                    continue
                disp = np.frombuffer(d, dtype=np.int32, count=pos_g.size,
                                     offset=off + int(pos_g[0]) + 1) if False else None
                # gather disps vectorized
                idx = pos_g + 1
                b0 = buf[idx].astype(np.uint32)
                b1 = buf[idx+1].astype(np.uint32)
                b2 = buf[idx+2].astype(np.uint32)
                b3 = buf[idx+3].astype(np.uint32)
                dispu = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
                disp = dispu.astype(np.int32)
                site_rva = off + pos_g + self.delta
                target = site_rva + 5 + disp
                yield off, pos_g.astype(np.int64), site_rva.astype(np.int64), target.astype(np.int64), opcode

    def callers_of_range(self, rva_lo, rva_hi):
        """All direct call/jmp sites in .text whose target lands in [lo,hi). Returns list of site RVAs."""
        sites = []
        for off, pos_g, site_rva, target, opcode in self.scan_direct():
            m = (target >= rva_lo) & (target < rva_hi)
            if m.any():
                sites.extend((int(site_rva[i]), int(target[i]), opcode) for i in np.flatnonzero(m))
        return sites

    def scan_riprel_all(self, targets_sorted):
        """Find all rip-relative disp32 references in .text to any RVA in sorted unique array targets_sorted.
        Returns list of (site_end_rva, target_rva, raw_disp). site_end_rva = rva of end of disp32 (=rip)."""
        d = self.pe.data
        ts = np.asarray(targets_sorted, dtype=np.int64)
        assert np.all(np.diff(ts) > 0)
        hits = []
        for off, n in self._chunks(1 << 24):
            # int32 view: from off to off+n (disp32 windows fully inside chunk)
            cnt = max(0, n - 3)
            if cnt <= 0:
                continue
            disps = np.frombuffer(d, dtype=np.int32, count=cnt, offset=off)
            p = np.arange(off, off + cnt, dtype=np.int64)
            # rip for instruction ending at p+4 : rva = p+4+delta ; target = rip + disp
            t = (p + 4 + self.delta) + disps
            i = np.searchsorted(ts, t)
            i_c = np.clip(i, 0, len(ts) - 1)
            m = ts[i_c] == t
            if m.any():
                for k in np.flatnonzero(m):
                    hits.append((int(p[k] + 4 + self.delta), int(ts[i_c[k]]), int(disps[k])))
        return hits

    def riprel_to(self, target_rva):
        return self.scan_riprel_all(np.array([target_rva], dtype=np.int64))

    def callgraph_targets(self):
        """Build full arrays of (site_rva, target_rva, opcode) for all direct E8/E9."""
        S, T, K = [], [], []
        for off, pos_g, site_rva, target, opcode in self.scan_direct():
            S.append(site_rva); T.append(target); K.append(np.full(len(site_rva), opcode, dtype=np.uint8))
        if not S:
            return None
        return np.concatenate(S), np.concatenate(T), np.concatenate(K)

    def find_func_of(self, rva):
        return self.pdata.find(rva)

# attach pdata lazily
def load():
    pe = PE()
    pd = Pdata(pe)
    sc = Scanner(pe)
    sc.pdata = pd
    return pe, pd, sc

if __name__ == '__main__':
    pe, pd, sc = load()
    print(f"File size: {len(pe.data):,}")
    print("Sections:")
    for s in pe.sections:
        print(f"  {s['name']:10s} vaddr=0x{s['vaddr']:08X} vsize=0x{s['vsize']:08X} raddr=0x{s['raddr']:08X} rsize=0x{s['rsize']:08X}")
    print("Data dirs:", [(i, hex(r), hex(sz)) for i, (r, sz) in enumerate(pe.dd) if r])
    print(f"Entry RVA: 0x{pe.entry_rva:X}")
    print(f".pdata entries: {len(pd.begins):,}")
    # verify known function
    for probe in (0x32495B9, 0x324ABD9, 0x3249CBE, 0xE09DA62, 0xE134B84):
        f = pd.find(probe)
        print(f"probe 0x{probe:X}: pdata -> {tuple(hex(x) for x in f) if f else None}, sec={pe.sec_of_rva(probe)['name'] if pe.sec_of_rva(probe) else '?'}")
