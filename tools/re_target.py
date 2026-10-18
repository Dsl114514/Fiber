#!/usr/bin/env python3
"""Analyze the function containing LEA ref to TextPacketPayload."""
import struct, sys, io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
data = open(path, 'rb').read()

def rva_to_off(rva):
    if 0x1000 <= rva < 0xDA8AC00: return 0x400 + (rva - 0x1000)
    if 0xDA8B000 <= rva < 0x10A9A600: return 0xDA8A000 + (rva - 0xDA8B000)
    if 0x1079B000 <= rva < 0x10C4DC00: return 0x10799600 + (rva - 0x1079B000)
    return -1

# The LEA instruction referencing TextPacketPayload
lea_rva = 0x03249CBE
lea_off = rva_to_off(lea_rva)
print(f"LEA instruction at RVA 0x{lea_rva:X} (file 0x{lea_off:X})")

# Read bytes around the LEA
ctx_off = lea_off - 32
ctx = data[ctx_off:lea_off + 80]
print(f"\nBytes around LEA (from 0x{ctx_off:X}):")
for i in range(0, len(ctx), 16):
    chunk = ctx[i:i+16]
    hexs = ' '.join(f'{b:02X}' for b in chunk)
    # ASCII
    asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  {ctx_off+i:08X}: {hexs:<48s} {asci}")

# Find function boundaries around this LEA
# Scan backwards for function prologue (sub rsp or push)
print("\n=== Function boundary search ===")
off = lea_off
# Backward for prologue
for back in range(0, 0x1000):
    a = off - back
    if a < 0x400: break
    chunk = data[a:a+5]
    # 48 83 EC xx (sub rsp, imm8) - common prologue
    if chunk[0] == 0x48 and chunk[1] == 0x83 and chunk[2] == 0xEC:
        print(f"  Prologue (sub rsp) at RVA 0x{0x1000 + (a - 0x400):X}")
        func_start = 0x1000 + (a - 0x400)
        break
    # 48 89 5C 24 (mov [rsp+...], rbx) - also common
    if chunk[0] == 0x48 and chunk[1] == 0x89:
        pass
    # RET before (function boundary)
    if data[a] == 0xC3 and data[a-1] != 0x00:
        print(f"  RET at RVA 0x{0x1000 + (a - 0x400):X}")
        # Function likely starts after this
        func_start = 0x1000 + (a - 0x400) + 1
        break

# Scan forward for function end (RET)
print("\n=== Forward scan for function end ===")
off = lea_off
for fwd in range(0, 0x2000):
    a = off + fwd
    if a >= 0xDA8A000: break
    if data[a] == 0xC3:
        # Check for ret with pop/leave before
        func_end = 0x1000 + (a - 0x400)
        print(f"  RET (function end) at RVA 0x{func_end:X}")
        break

print("\nDone")