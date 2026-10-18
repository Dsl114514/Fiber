#!/usr/bin/env python3
"""Analyze the TRUE function entry (from .pdata) for TextPacketPayload handler."""
import struct, sys, io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
data = open(path, 'rb').read()

def rva_to_off(rva):
    if 0x1000 <= rva < 0xDA8AC00: return 0x400 + (rva - 0x1000)
    if 0xDA8B000 <= rva < 0x10A9A600: return 0xDA8A000 + (rva - 0xDA8B000)
    return -1

# TRUE function range from .pdata
func_start = 0x3242680
func_end = 0x324C0BA

off = rva_to_off(func_start)
print(f"TRUE Function: RVA 0x{func_start:X} - 0x{func_end:X}")
print(f"Size: 0x{func_end - func_start:X} bytes\n")

print("=== Function prologue (first 96 bytes) ===")
for i in range(0, 96, 16):
    chunk = data[off+i:off+i+16]
    hexs = ' '.join(f'{b:02X}' for b in chunk)
    asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  {func_start+i:08X}: {hexs:<48s} {asci}")

# Determine calling convention from prologue
# x64: RCX=arg1, RDX=arg2, R8=arg3, R9=arg4, stack for rest
print("\n=== Signature analysis ===")
# Look for usage of RCX/RDX/R8/R9 early in function (parameter usage)
# Common: mov [rbp+x], rcx (store this), mov [rbp+y], rdx (store arg2)
for i in range(0, 96):
    b = data[off+i]
    if b == 0x48 and i+1 < 96:
        b1 = data[off+i+1]
        # mov [rbp+disp], rcx = 48 89 8D
        if b1 == 0x89 and data[off+i+2] in (0x4D, 0x4C, 0x8D):
            pass
# Just show first 3 instructions decoded manually
print("  Looking at parameter register saves (RCX=this, RDX=arg1, R8=arg2, R9=arg3)...")

# Check if this looks like a virtual function (has vtable dispatch)
# Search for RTTI reference to class that owns this function
# The .pdata unwind says frame reg = 0x85 (RBP), so it uses RBP frame

# Find the vtable / RTTI for the class
# Search near the function for class identification
print("\n=== Search for owning class (vtable/RTTI) ===")
# Common pattern: the function is called via vtable, and there's RTTI nearby
# Search the .rdata near the TextPacketPayload string for class names
tp_rva = 0xE134B84
tp_off = rva_to_off(tp_rva)
# Look around the payload string for the owning class RTTI
for delta in range(-0x500, 0x1000, 1):
    a = tp_off + delta
    if a < 0 or a > len(data)-20: continue
    # Look for "?AV" (class type descriptor) patterns
    if data[a:a+4] == b'.?AV':
        s = data[a:a+80].split(b'\x00')[0]
        try:
            print(f"  RTTI at {a:X}: {s.decode()}")
        except:
            pass

# Analyze how the function is called (find callers)
print("\n=== Find callers of this function ===")
text_start, text_end = 0x400, 0xDA8A000
text_rva = 0x1000
calls = []
pos = 0
while True:
    i = data.find(b'\xE8', text_start + pos)
    if i < 0 or i > text_end: break
    if i + 5 <= text_end:
        disp = struct.unpack_from('<I', data, i+1)[0]
        call_rva = text_rva + (i - text_start)
        target = (call_rva + 5 + disp) & 0xFFFFFFFF
        if target == func_start:
            calls.append(call_rva)
    pos = i + 1 - text_start
    if len(calls) > 20: break

print(f"  Direct CALLers: {len(calls)}")
for c in calls[:20]:
    print(f"    CALL at RVA 0x{c:X}")

print("\nDONE")