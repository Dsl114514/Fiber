"""用 .pdata 异常目录验证主循环候选:判定候选 RVA 是函数体还是"指向函数的指针槽"。

用法: python ml_pdata.py
"""
import struct, json, bisect, os, sys

EXE = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
HERE = os.path.dirname(os.path.abspath(__file__))

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

# ---- .pdata: RUNTIME_FUNCTION {Begin, End, Unwind} 12 bytes each ----
prva, psize = dirs[3]
poff = r2o(prva)
n = psize // 12
funcs = []
for i in range(n):
    b, en, uw = struct.unpack_from('<III', d, poff + 12 * i)
    if b == 0 or en <= b:
        continue
    funcs.append((b, en))
funcs.sort()
begins = [f[0] for f in funcs]
print(f".pdata: {n:,} entries, {len(funcs):,} valid functions")

def containing(rva):
    i = bisect.bisect_right(begins, rva) - 1
    if i >= 0:
        b, en = funcs[i]
        if b <= rva < en:
            return (b, en)
    return None

TEXT_LO, TEXT_HI = 0x1000, 0xDA8AB56

def classify(rva, label):
    out = [f"--- {label}  RVA=0x{rva:X}  sec={sec_of(rva)}"]
    o = r2o(rva)
    if o is None:
        out.append("    (无法映射文件偏移)")
        return out
    raw = d[o:o + 32]
    out.append("    bytes: " + ' '.join(f"{x:02X}" for x in raw[:16]))
    # 1) 是否函数体?
    c = containing(rva)
    if c:
        out.append(f"    函数体: [0x{c[0]:X}, 0x{c[1]:X})  大小=0x{c[1]-c[0]:X} ({c[1]-c[0]} 字节)")
    # 2) 是否"指向函数的指针槽"?(8 字节 = 合法 .text RVA 且 .pdata 中恰有该函数起点)
    p = struct.unpack_from('<Q', d, o)[0]
    if TEXT_LO <= p < TEXT_HI:
        cf = None
        i = bisect.bisect_left(begins, p)
        if i < len(funcs) and funcs[i][0] == p:
            cf = funcs[i]
        tag = "★ 精确函数起点" if cf else "(.text 内,非函数起点)"
        out.append(f"    首 8 字节解引用 = 0x{p:X} {tag}"
                   + (f" → 函数 [0x{cf[0]:X}, 0x{cf[1]:X}) 大小=0x{cf[1]-cf[0]:X}" if cf else ""))
    if not c and not (TEXT_LO <= p < TEXT_HI):
        out.append("    既非函数体也非函数指针槽(可能是 .rdata 数据/字符串)")
    return out

# ---- 候选集 ----
c10 = json.load(open(os.path.join(HERE, 'research_scripts', 'c10_pairs.json'), encoding='utf-8'))
c4 = json.load(open(os.path.join(HERE, 'research_scripts', 'c4_sigrvas.json'), encoding='utf-8'))

print("\n================ A. c10_pairs 代码引用点(RTTI 名字的反向引用) ================")
for rva_s, names in c10.items():
    for line in classify(int(rva_s, 16), names[0][:70]):
        print(line)

print("\n================ B. c4_sigrvas RTTI 签名串位置 ================")
for name, rvas in c4.items():
    for rva_s in rvas:
        for line in classify(int(rva_s, 16), name[:70]):
            print(line)