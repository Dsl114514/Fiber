"""Fixed pointer scan:
  detect whether .rdata/.data store vtables as bare RVAs or as absolute VAs (ImageBase + RVA),
  then locate slots holding each candidate, and report vtable-like neighbourhoods.
"""
import struct, bisect

EXE = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
d = open(EXE, 'rb').read()

e = struct.unpack_from('<I', d, 0x3C)[0]
coff = e + 4
machine, nsec, _, _, _, optsize, chars = struct.unpack_from('<HHIIIHH', d, coff)
opt = coff + 20
magic = struct.unpack_from('<H', d, opt)[0]
image_base = struct.unpack_from('<Q', d, opt + 24)[0]
dd = opt + (112 if magic == 0x20b else 96)
dirs = [struct.unpack_from('<II', d, dd + 8 * i) for i in range(16)]
secs = []
off = opt + optsize
for i in range(nsec):
    nm, vs, va, rs, ro, _, _, _, _, _ = struct.unpack_from('<8sIIIIIIHHI', d, off + 40 * i)
    secs.append((nm.rstrip(b'\0').decode('latin1'), va, vs, ro, rs))

def r2o(rva):
    for nm, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

def sec_of(rva):
    for nm, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return nm
    return '?'

print(f"ImageBase = 0x{image_base:X}")

TEXT_LO, TEXT_HI = 0x1000, 0xDA8AB56
prva, psize = dirs[3]
poff = r2o(prva)
funcs = []
for i in range(psize // 12):
    b, en, uw = struct.unpack_from('<III', d, poff + 12 * i)
    if b and en > b:
        funcs.append((b, en))
funcs.sort()
begins = [f[0] for f in funcs]
fstart = set(begins)

def containing(rva):
    i = bisect.bisect_right(begins, rva) - 1
    if i >= 0:
        b, en = funcs[i]
        if b <= rva < en:
            return (b, en)
    return None

CANDS = {
    0x879E10: 'MinecraftGame::update #1',
    0x87A530: 'MinecraftGame::update #2',
    0x87AB10: 'MinecraftGame::update #3',
    0x87AC90: 'MinecraftGame::update big',
    0x1D60D40: 'ServerInstance::_update big',
    0x1D5E7D0: 'ServerInstance::_update 225B',
    0x1D77260: 'ServerLevel::_subTick 403B',
    0x1D64ED0: 'ServerLevel::_subTick 581B',
    0x1D65410: 'ServerLevel::_subTick 437B',
    0x31D990: 'ServerInstance::_update 52B',
    0x1D5E6B0: 'ServerInstance::_update 131B-a',
    0x1D5E740: 'ServerInstance::_update 131B-b',
    0x729BA0: 'BackgroundWorker::_runOneTask',
}

for nm in ('.rdata', '.data'):
    s = next(x for x in secs if x[0] == nm)
    _, va, vs, ro, rs = s
    blob = d[ro:ro + rs]
    cnt_bare = cnt_va = 0
    for j in range(0, rs - 8, 8):
        v = struct.unpack_from('<Q', blob, j)[0]
        if TEXT_LO <= v < TEXT_HI:
            cnt_bare += 1
        elif TEXT_LO <= v - image_base < TEXT_HI:
            cnt_va += 1
    print(f"\n### {nm}: 8-byte slots pointing into .text -> bare-RVA={cnt_bare:,}   VA(ImageBase+)= {cnt_va:,}")

    for rva, label in CANDS.items():
        for mode, pat in (('RVA', struct.pack('<Q', rva)),
                          ('VA ', struct.pack('<Q', image_base + rva))):
            hits = []
            st = 0
            while True:
                j = blob.find(pat, st)
                if j < 0: break
                if j % 8 == 0:
                    hits.append(va + j)
                st = j + 1
                if len(hits) > 30: break
            if hits:
                # neighbourhood: count how many of the 8 preceding slots also point into .text
                j0 = hits[0] - va
                nbr = 0
                for k in range(1, 9):
                    jj = j0 - 8 * k
                    if jj < 0: break
                    v = struct.unpack_from('<Q', blob, jj)[0]
                    vv = v if mode == 'RVA' else v - image_base
                    if TEXT_LO <= vv < TEXT_HI:
                        nbr += 1
                print(f"   [{mode}] {label:32} 0x{rva:X}: {len(hits)} slot(s) first=0x{hits[0]:X} "
                      f"({sec_of(hits[0])}) preceding-text-ptrs={nbr}/8")