#!/usr/bin/env python3
"""exe_extra5.py - brute-force NRV2B micro-variants on gdk_patch.dll stream.
Stream layout per stub disasm: single shared pointer; 32-bit LE bit-word refills
interleaved with literal/match bytes. Validate via MZ + sane PE parse."""
import struct
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
GP = r"E:\mcb\bedrock_versions\1.26.3301\preload\gdk_patch.dll"
OUT = r"E:\mcb\Fiber\docs\gdk_patch_unpacked.bin"

with open(GP, "rb") as f:
    g = f.read()
sz_unc, sz_cmp = 0xA798, 0x3393
src = g[0x400:0x400 + sz_cmp]  # stream only


def make_decompress(bit_order="msb", off_loop="b1", copy="c1", big_off=True):
    """bit_order: msb = bits MSB-first from LE32 refill; lsb = LSB-first.
    off_loop: b1 = do{m=m*2+bit}while(!bit); b2 adds (m-1)*2+bit step.
    copy: c1 = 2 unrolled + m_len extra; c3 = m_len total."""
    def getbit(state):
        bb = state["bb"]
        if bit_order == "msb":
            bit = (bb >> 31) & 1
            bb = (bb << 1) & 0xFFFFFFFF
        else:
            bit = bb & 1
            bb = bb >> 1
        if bb == 0:
            if state["ip"] + 4 > len(src):
                raise EOFError("stream exhausted")
            bb = struct.unpack_from("<I", src, state["ip"])[0]
            state["ip"] += 4
            if bit_order == "msb":
                bit = (bb >> 31) & 1
                bb = (bb << 1) & 0xFFFFFFFF
            else:
                bit = bb & 1
                bb = bb >> 1
        state["bb"] = bb
        return bit

    def run():
        state = {"bb": 0, "ip": 0}
        dst = bytearray()
        last = 1
        gb = lambda: getbit(state)
        try:
            while True:
                while gb():
                    dst.append(src[state["ip"]]); state["ip"] += 1
                    if len(dst) > sz_unc:
                        return None, dst
                m_off = 1
                while True:
                    m_off = m_off * 2 + gb()
                    if gb():
                        break
                    if off_loop == "b2":
                        m_off = (m_off - 1) * 2 + gb()
                if m_off == 2:
                    m_off = last
                else:
                    m_off = (m_off - 3) * 256 + src[state["ip"]]
                    state["ip"] += 1
                    if m_off == 0xFFFFFFFF:
                        return "EOF", dst
                    m_off += 1
                    last = m_off
                m_len = gb()
                m_len = m_len * 2 + gb()
                if m_len == 0:
                    m_len += 1
                    while True:
                        m_len = m_len * 2 + gb()
                        if gb():
                            break
                    m_len += 2
                if big_off and m_off > 0xD00:
                    m_len += 1
                if m_off > len(dst):
                    raise ValueError(f"m_off {m_off:#x} > {len(dst):#x} at ip={state['ip']:#x}")
                if copy == "c1":
                    dst.append(dst[-m_off]); dst.append(dst[-m_off])
                    for _ in range(m_len):
                        dst.append(dst[-m_off])
                else:
                    for _ in range(m_len + 2):
                        dst.append(dst[-m_off])
                if len(dst) > sz_unc + 64:
                    return None, dst
        except (EOFError, ValueError, IndexError, struct.error) as ex:
            return f"fail:{ex}", dst
    return run


results = []
for bit_order in ("msb", "lsb"):
    for off_loop in ("b1", "b2"):
        for copy in ("c1", "c3"):
            for big_off in (True, False):
                tag, out = make_decompress(bit_order, off_loop, copy, big_off)()
                ok = tag == "EOF" and len(out) == sz_unc and out[:2] == b"MZ"
                results.append((ok, tag, bit_order, off_loop, copy, big_off, out))
                print(f"bit={bit_order} off={off_loop} copy={copy} big={big_off}: {tag} len=0x{len(out):X} head={out[:4].hex(' ')}")

ok = [r for r in results if r[0]]
if ok:
    best = ok[0]
    out = best[6]
    print(f"\n*** WINNER: bit={best[2]} off={best[3]} copy={best[4]} big={best[5]} len=0x{len(out):X}")
    with open(OUT, "wb") as f:
        f.write(out)
    # strings from whole unpacked image
    print("\n== strings >=6 chars in unpacked gdk_patch ==")
    seen = set()
    for m in re.finditer(rb"[\x20-\x7E]{6,}", out):
        s = m.group().decode("ascii")
        if s in seen:
            continue
        seen.add(s)
        print(f"   0x{m.start():05X}: {s[:150]}")
else:
    print("\nno variant fully validated; dumping best-effort strings from largest outputs")
    cand = max(results, key=lambda r: len(r[6]))
    print(f"best candidate: {cand[1]} bit={cand[2]} off={cand[3]} copy={cand[4]} len=0x{len(cand[6]):X}")
