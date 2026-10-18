#!/usr/bin/env python3
"""Confirm LEA target and function containing TextPacketPayload reference."""
import struct, sys, io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
data = open(path, 'rb').read()

def off_to_rva(off):
    if 0x400 <= off < 0xDA8A000: return 0x1000 + (off - 0x400)          # .text
    if 0xDA8A000 <= off < 0x10A99600: return 0xDA8B000 + (off - 0xDA8A000) # .rdata
    if 0x10799600 <= off < 0x10C4DC00: return 0x1079B000 + (off - 0x10799600) # .data
    return -1

# Verify TextPacketPayload string RVA
tp_off = data.find(b'TextPacketPayload')
print(f"TextPacketPayload string at file=0x{tp_off:X}, RVA=0x{off_to_rva(tp_off):X}")

# The LEA instruction found
lea_off = 0x32490BE  # file offset of the 48 8D 05 instruction
lea_rva = 0x1000 + (lea_off - 0x400)
disp = struct.unpack_from('<I', data, lea_off + 3)[0]
target = (lea_rva + 7 + disp) & 0xFFFFFFFF
print(f"LEA at RVA=0x{lea_rva:X}, disp=0x{disp:X}")
print(f"LEA target RVA=0x{target:X}")

# What string is at that target?
if 0xDA8B000 <= target < 0x10A9A600:
    toff = 0xDA8A000 + (target - 0xDA8B000)
    s = data[toff:toff+60].split(b'\x00')[0]
    print(f"  String at target: '{s.decode(errors='replace')}'")

# Function containing this LEA
# From earlier scan: function start after RET at RVA 0x32495B9, end at 0x324ABD9
func_start = 0x32495B9
func_end = 0x324ABD9
func_size = func_end - func_start
print(f"\nFunction: RVA 0x{func_start:X} - 0x{func_end:X} (size 0x{func_size:X})")

# Disassemble-ish: find all LEA rip-rel and CALLs in the function
f_start_off = rva_to_off if False else (0x400 + (func_start - 0x1000))
f_end_off = 0x400 + (func_end - 0x1000)
print(f"Function file range: 0x{f_start_off:X} - 0x{f_end_off:X}")

# Find CALLs and LEA rip-rel within function
calls = []
leas = []
pos = f_start_off
while pos < f_end_off - 5:
    b = data[pos]
    if b == 0xE8:  # call rel32
        d = struct.unpack_from('<I', data, pos+1)[0]
        rva = 0x1000 + (pos - 0x400)
        t = (rva + 5 + d) & 0xFFFFFFFF
        calls.append((rva, t))
        pos += 5
    elif b == 0x48 and pos+2 < f_end_off and data[pos+1] == 0x8D and data[pos+2] in (0x05,0x0D,0x0C,0x0E):
        d = struct.unpack_from('<I', data, pos+3)[0]
        rva = 0x1000 + (pos - 0x400)
        t = (rva + 7 + d) & 0xFFFFFFFF
        # Resolve string if in rdata
        label = f"0x{t:X}"
        if 0xDA8B000 <= t < 0x10A9A600:
            toff = 0xDA8A000 + (t - 0xDA8B000)
            s = data[toff:toff+40].split(b'\x00')[0]
            if len(s) > 3 and all(32 <= c < 127 for c in s):
                label = f"'{s.decode()}'"
        leas.append((rva, t, label))
        pos += 7
    else:
        pos += 1

print(f"\nCALLs in function ({len(calls)}):")
for rva, t in calls[:20]:
    print(f"  CALL 0x{rva:X} -> 0x{t:X}")

print(f"\nLEA rip-rel in function ({len(leas)}):")
for rva, t, label in leas[:20]:
    print(f"  LEA 0x{rva:X} -> {label}")

print("\nDONE")