"""Resolve the vtable(s) containing the mainloop candidates and read their RTTI
CompleteObjectLocator -> TypeDescriptor -> decorated class name.
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

TEXT_LO, TEXT_HI = 0x1000, 0xDA8AB56
RD = next(s for s in secs if s[0] == '.rdata')
_, RD_VA, _, RD_RO, RD_RS = RD

def slot(rva):
    """read 8-byte slot value at .rdata rva"""
    o = r2o(rva)
    return struct.unpack_from('<Q', d, o)[0]

def run_start(rva):
    """walk back while slots are text pointers"""
    cur = rva
    while True:
        prev = cur - 8
        v = slot(prev)
        if TEXT_LO <= v - image_base < TEXT_HI:
            cur = prev
        else:
            break
    return cur

def run_end(rva):
    cur = rva
    while True:
        nxt = cur + 8
        v = slot(nxt)
        if TEXT_LO <= v - image_base < TEXT_HI:
            cur = nxt
        else:
            break
    return cur

def col_name(col_rva):
    o = r2o(col_rva)
    if o is None: return None
    sig, off_, cd, td, ptd, pcd = struct.unpack_from('<IIIIII', d, o)
    if sig not in (0, 1):
        return f"<bad COL signature {sig}>"
    # ptd is an RVA to TypeDescriptor
    o2 = r2o(ptd)
    if o2 is None: return f"<bad TypeDescriptor rva 0x{ptd:X}>"
    pvf, spare = struct.unpack_from('<QQ', d, o2)
    name = d[o2 + 16: d.index(b'\0', o2 + 16)].decode('latin1', 'replace')
    return f"sig={sig} td=0x{ptd:X} name={name}"

def analyse(seed_rva, label):
    st, en = run_start(seed_rva), run_end(seed_rva)
    nslots = (en - st) // 8 + 1
    print(f"\n### {label}: slot 0x{seed_rva:X}")
    print(f"    contiguous text-pointer run: 0x{st:X} .. 0x{en:X}  ({nslots} slots)")
    # COL pointer sits right before the run start
    col = slot(st - 8)
    print(f"    word before run: 0x{col:X}", end='  ')
    if RD_VA <= col - image_base < RD_VA + RD_RS:
        print(f"-> looks like a COL/VTable pointer into .rdata (rva 0x{col-image_base:X})")
        print("    RTTI:", col_name(col - image_base))
    else:
        print("-> not a .rdata pointer (maybe run continues past a header)")
    # print slot indices of candidates within the run
    for rva, nm in CANDS.items():
        if st <= rva <= en:
            print(f"      slot #{ (rva - st)//8 }  0x{rva:X}  {nm}")

CANDS = {
    0x879E10: 'update#1',
    0x87A530: 'update#2',
    0x87AB10: 'update#3',
    0x87AC90: 'update-big',
    0x1D60D40: 'ServerInstance::_update-big',
    0x1D5E7D0: 'ServerInstance::_update-225B',
    0x1D5E6B0: 'ServerInstance::_update-131B-a',
    0x1D5E740: 'ServerInstance::_update-131B-b',
    0x31D990: 'ServerInstance::_update-52B',
    0x1D77260: 'ServerLevel::_subTick-403B',
    0x1D64ED0: 'ServerLevel::_subTick-581B',
    0x1D65410: 'ServerLevel::_subTick-437B',
    0x729BA0: 'BackgroundWorker::_runOneTask',
}

for seed, label in ((0xDBDADB0, 'MinecraftGame update vtable'),
                   (0xDCC7380, 'ServerInstance/_update vtable'),
                   (0xDCC8190, 'ServerLevel::_subTick vtable'),
                   (0xDB8ECF0, 'ServerInstance::_update-52B vtable'),
                   (0xDBD6940, 'BackgroundWorker vtable')):
    analyse(seed, label)