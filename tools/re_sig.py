#!/usr/bin/env python3
"""Analyze TextPacketPayload handler function prologue & signature."""
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

func_start = 0x32495B9
func_end = 0x324ABD9

off = rva_to_off(func_start)
print(f"Function: RVA 0x{func_start:X}, file offset 0x{off:X}")
print(f"Function size: 0x{func_end - func_start:X} bytes\n")

# Dump first 64 bytes of prologue
print("=== Prologue (first 64 bytes) ===")
for i in range(0, 64, 16):
    chunk = data[off+i:off+i+16]
    hexs = ' '.join(f'{b:02X}' for b in chunk)
    asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  {func_start+i:08X}: {hexs:<48s} {asci}")

# Also dump bytes just BEFORE the function (to find the true start)
print("\n=== Bytes before function start (looking for prologue) ===")
for i in range(-16, 0, 16):
    chunk = data[off+i:off+i+16]
    hexs = ' '.join(f'{b:02X}' for b in chunk)
    print(f"  {func_start+i:08X}: {hexs}")

# Analyze the LEA reference to TextPacketPayload more carefully
# The LEA at 0x3249CBE loads RAX = &TextPacketPayload string
# Look at what happens with RAX after that LEA
print("\n=== Context around LEA to TextPacketPayload ===")
lea_off = rva_to_off(0x3249CBE)
for i in range(-32, 48, 16):
    start = lea_off + i
    chunk = data[start:start+16]
    hexs = ' '.join(f'{b:02X}' for b in chunk)
    asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"  {0x1000+(start-0x400):08X}: {hexs:<48s} {asci}")

# Check .pdata for this function (unwind info reveals signature/stack)
# Search for .pdata entry covering this function
# .pdata section: file 0x10C4DC00, RVA 0x10F5C000
print("\n=== Search .pdata for unwind info ===")
# .pdata entries are 12 bytes each: BeginAddress, EndAddress, UnwindInfo
pdata_off = 0x10C4DC00
pdata_size = 0x9C9600
found = None
for i in range(0, pdata_size - 12, 12):
    begin, end, unwind = struct.unpack_from('<III', data, pdata_off + i)
    # Convert .pdata RVAs (they're relative to ImageBase)
    # .pdata BeginAddress is an RVA
    if begin <= func_start < end:
        found = (begin, end, unwind, pdata_off + i)
        break

if found:
    begin, end, unwind, entry_off = found
    print(f"  .pdata entry: begin=0x{begin:X} end=0x{end:X} unwind=0x{unwind:X}")
    print(f"  Unwind info at RVA 0x{unwind:X}")
    # Parse unwind info
    u_off = rva_to_off(unwind)
    if u_off > 0:
        print(f"  Unwind info file offset: 0x{u_off:X}")
        # First 4 bytes: version+flags(1), size of prologue(1), count of codes(1), frame reg(1)
        ver_flags, prolog_size, codes_count, frame_reg = struct.unpack_from('<BBBB', data, u_off)
        print(f"  Version/Flags: 0x{ver_flags:X}  Prologue size: 0x{prolog_size:X}  Codes: {codes_count}  FrameReg: 0x{frame_reg:X}")
        # Unwind codes follow
        if codes_count > 0:
            for c in range(codes_count):
                off_lo, off_hi, op, opinfo = struct.unpack_from('<BBBB', data, u_off + 4 + c*2)
                print(f"    Code[{c}]: offset=0x{off_lo|(off_hi<<8):X} op=0x{op:X} opinfo=0x{opinfo:X}")
        # Find .xdata if referenced
        if 0xDA8B000 <= unwind < 0x10A9A600:
            xd_off = 0xDA8A000 + (unwind - 0xDA8B000)
            if xd_off < len(data) - 100:
                print(f"\n  .xdata raw ({xd_off:X}):")
                for i in range(0, 40, 16):
                    chunk = data[xd_off+i:xd_off+i+16]
                    hexs = ' '.join(f'{b:02X}' for b in chunk)
                    print(f"    {unwind+i:08X}: {hexs}")
else:
    print("  No .pdata entry found")

print("\nDONE")