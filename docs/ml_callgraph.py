"""候选主循环函数的调用图取证:
  A. 在 .rdata 中搜索指向候选的 8 字节指针(= 是否出现在虚表/函数指针表)
  B. 在 .text 中搜索 E8 rel32 直接调用候选(= 谁调用它,并用 .pdata 定位调用者函数)
输出英文标签以避免控制台编码问题。
"""
import struct, bisect, os, collections

EXE = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
d = open(EXE, 'rb').read()

e = struct.unpack_from('<I', d, 0x3C)[0]
coff = e + 4
machine, nsec, _, _, _, optsize, chars = struct.unpack_from('<HHIIIHH', d, coff)
opt = coff + 20
magic = struct.unpack_from('<H', d, opt)[0]
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

# .pdata function table
prva, psize = dirs[3]
poff = r2o(prva)
funcs = []
for i in range(psize // 12):
    b, en, uw = struct.unpack_from('<III', d, poff + 12 * i)
    if b and en > b:
        funcs.append((b, en))
funcs.sort()
begins = [f[0] for f in funcs]

def containing(rva):
    i = bisect.bisect_right(begins, rva) - 1
    if i >= 0:
        b, en = funcs[i]
        if b <= rva < en:
            return (b, en)
    return None

CANDS = {
    0x879E10: 'MinecraftGame::update(xref#1)',
    0x87A530: 'MinecraftGame::update(xref#2)',
    0x87AB10: 'MinecraftGame::update(xref#3)',
    0x87AC90: 'MinecraftGame::update(big 15KB)',
    0x1D60D40: 'ServerInstance::_update(big 9.8KB)',
    0x1D5E7D0: 'ServerInstance::_update(225B)',
    0x1D771B0: 'ServerInstance::_update(43B)',
    0x1D77260: 'ServerLevel::_subTick(403B)',
    0x1D64ED0: 'ServerLevel::_subTick(581B)',
    0x1D65410: 'ServerLevel::_subTick(437B)',
    0x31D990:  'ServerInstance::_update(52B)',
    0x1D5E6B0: 'ServerInstance::_update(131B)',
    0x1D5E740: 'ServerInstance::_update(131B)',
    0x729BA0:  'BackgroundWorker::_runOneTask(517B)',
    0x729DD0:  'BackgroundWorker::_runOneTask/Scheduler(180B)',
}

print("=== A. pointers to candidates inside .rdata / .data (vtable or fn-ptr table presence) ===")
rd = next(s for s in secs if s[0] == '.rdata')
dt = next(s for s in secs if s[0] == '.data')
for scan_sec in (rd, dt):
    nm, va, vs, ro, rs = scan_sec
    blob = d[ro:ro + rs]
    print(f"-- scanning {nm} (rva 0x{va:X}, {rs:,} bytes)")
    for rva, label in CANDS.items():
        pat = struct.pack('<Q', rva)
        hits = []
        start = 0
        while True:
            j = blob.find(pat, start)
            if j < 0: break
            hits.append(va + j)
            start = j + 1
            if len(hits) > 40: break
        if hits:
            secn = sec_of(hits[0])
            print(f"   {label:42} 0x{rva:X}: {len(hits)} ptr(s), first=0x{hits[0]:X} ({secn})")

print("\n=== B. direct E8 callers (call rel32) inside .text ===")
tx = next(s for s in secs if s[0] == '.text')
nm, va, vs, ro, rs = tx
blob = d[ro:ro + rs]
targets = {r: [] for r in CANDS}
i = 0
n = len(blob)
while True:
    i = blob.find(b'\xe8', i)
    if i < 0: break
    if i + 5 <= n:
        rel = struct.unpack_from('<i', blob, i + 1)[0]
        call_site_rva = va + i
        tgt = call_site_rva + 5 + rel
        if tgt in targets:
            targets[tgt].append(call_site_rva)
    i += 1

for rva, label in CANDS.items():
    callers = targets[rva]
    caller_funcs = collections.Counter()
    for c in callers:
        f = containing(c)
        caller_funcs[f] += 1
    print(f"-- {label:42} 0x{rva:X}: {len(callers)} direct call(s)")
    for c in callers[:6]:
        f = containing(c)
        fr = f"[caller func 0x{f[0]:X}-0x{f[1]:X}]" if f else "[no unwind info]"
        print(f"      call at 0x{c:X}  {fr}")
    if len(callers) > 6:
        print(f"      ... (+{len(callers)-6} more)")