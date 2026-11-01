import struct, sys, math

def entropy(b):
    if not b: return 0.0
    cnt = [0]*256
    for x in b: cnt[x] += 1
    n = len(b)
    return -sum((c/n)*math.log2(c/n) for c in cnt if c)

def parse(path):
    d = open(path, 'rb').read()
    print(f"=== {path}  ({len(d):,} bytes) ===")
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e+4] != b'PE\0\0':
        print("  not PE"); return None
    coff = e + 4
    machine, nsec, tds, _, _, optsize, chars = struct.unpack_from('<HHIIIHH', d, coff)
    print(f"  machine=0x{machine:x} sections={nsec} characteristics=0x{chars:x} optsize={optsize}")
    opt = coff + 20
    magic = struct.unpack_from('<H', d, opt)[0]
    print(f"  optmagic=0x{magic:x}  subsystem=0x{struct.unpack_from('<H',d,opt+68)[0]:x}")
    dd = opt + (112 if magic == 0x20b else 96)
    dirs = [struct.unpack_from('<II', d, dd+8*i) for i in range(16)]
    dnames = ['export','import','resource','exception','certificate','reloc','debug','arch',
              'globalptr','tls','loadcfg','bound','iat','delayimport','clr','reserved']
    for i,(rva,size) in enumerate(dirs):
        if size: print(f"    dir[{i:2}] {dnames[i]:12} rva=0x{rva:x} size=0x{size:x}")
    secs = []
    off = opt + optsize
    for i in range(nsec):
        nm, vs, va, rs, ro, _, _, _, _, _ = struct.unpack_from('<8sIIIIIIHHI', d, off+40*i)
        nm = nm.rstrip(b'\0').decode('latin1')
        secs.append((nm, va, vs, ro, rs))
        body = d[ro:ro+min(rs, 1<<20)]
        print(f"    sec {nm:8} rva=0x{va:x} vsize=0x{vs:x} file=0x{ro:x} rsize=0x{rs:x} H={entropy(body):.2f}")
    def r2o(rva):
        for nm, va, vs, ro, rs in secs:
            if va <= rva < va + max(vs, rs): return ro + (rva - va)
        return None
    def cstr(o):
        if o is None: return '?'
        end = d.index(b'\0', o)
        return d[o:end].decode('latin1', 'replace')
    if dirs[1][1]:
        o = r2o(dirs[1][0]); print("  -- STATIC IMPORTS --")
        while True:
            ilt, ts, fc, name, iat = struct.unpack_from('<IIIII', d, o)
            if name == 0 and ilt == 0 and iat == 0: break
            print("     *", cstr(r2o(name)))
            o += 20
    if dirs[13][1]:
        o = r2o(dirs[13][0]); print("  -- DELAY IMPORTS --")
        while True:
            attrs, name, mod, iat, intt, bound, uiat, ts, tstamp = struct.unpack_from('<IIIIIIIII', d, o)
            if name == 0: break
            print(f"     * {cstr(r2o(name))}  (attrs=0x{attrs:x} iat=0x{iat:x})")
            o += 32
    if dirs[0][1]:
        o = r2o(dirs[0][0])
        f = struct.unpack_from('<IIHHIIIIIII', d, o)
        base, nfunc, nname, af, an, ao = f[5], f[6], f[7], f[8], f[9], f[10]
        print(f"  -- EXPORTS -- count={nfunc} names={nname} ordbase={base}")
        for i in range(min(nname, 40)):
            nrva = struct.unpack_from('<I', d, r2o(an) + 4*i)[0]
            print("     *", cstr(r2o(nrva)))
    if dirs[9][1]:
        t = r2o(dirs[9][0])
        sd, rd, idx, cb, zf, chars_tls = struct.unpack_from('<QQQQII', d, t)
        print(f"  -- TLS -- raw={rd:x} cb={cb} callbacks={cb:x} zero_fill={zf}")
        if cb:
            co = r2o(cb)
            if co:
                p = struct.unpack_from('<Q', d, co)[0]
                print(f"     first callback VA=0x{p:x}")
    return d

for p in sys.argv[1:]:
    parse(p)
    print()