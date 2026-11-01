"""Dump candidate function prologues (32 bytes) as future pattern-scan anchors."""
import struct

EXE = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
d = open(EXE, 'rb').read()
e = struct.unpack_from('<I', d, 0x3C)[0]
coff = e + 4
_, nsec, _, _, _, optsize, _ = struct.unpack_from('<HHIIIHH', d, coff)
opt = coff + 20
magic = struct.unpack_from('<H', d, opt)[0]
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

CANDS = [
    (0x87AC90, 'MinecraftGame::update-big(15KB)'),
    (0x879E10, 'MinecraftGame::update#1'),
    (0x87A530, 'MinecraftGame::update#2'),
    (0x87AB10, 'MinecraftGame::update#3'),
    (0x1D60D40, 'ServerInstance::_update-big(9.8KB)'),
    (0x1D5E7D0, 'ServerInstance::_update(225B)'),
    (0x1D77260, 'ServerLevel::_subTick(403B)'),
    (0x1D64ED0, 'ServerLevel::_subTick(581B)'),
    (0x1D65410, 'ServerLevel::_subTick(437B)'),
]
print("candidate prologues (32 bytes) — future pattern anchors")
for rva, label in CANDS:
    o = r2o(rva)
    raw = d[o:o + 32]
    print(f"0x{rva:X}  {label}")
    print("    " + ' '.join(f"{x:02X}" for x in raw))
    print("    mask= " + ' '.join('??' if i >= 8 else f"{x:02X}" for i, x in enumerate(raw)))