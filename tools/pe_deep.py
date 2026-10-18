#!/usr/bin/env python3
"""Deep PE analysis for Minecraft Bedrock."""
import struct
import sys
import io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = sys.stdout

path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
data = open(path, 'rb').read()

print(f"File size: {len(data):,} bytes ({len(data)/1024/1024:.1f} MB)")

# Parse PE header properly
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
print(f"PE header at: 0x{e_lfanew:X}")

# COFF header
machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt_size = struct.unpack_from('<H', data, e_lfanew + 16)[0]
chars = struct.unpack_from('<H', data, e_lfanew + 18)[0]

print(f"Machine: {hex(machine)} ({'x64' if machine == 0x8664 else 'x86' if machine == 0x14c else 'other'})")
print(f"Sections: {num_sec}")
print(f"Optional header size: {hex(opt_size)}")
print(f"Characteristics: {hex(chars)}")

# Optional header
opt_off = e_lfanew + 24
magic = struct.unpack_from('<H', data, opt_off)[0]
print(f"Magic: {hex(magic)} ({'PE32+' if magic == 0x20B else 'PE32' if magic == 0x10B else 'unknown'})")

# Standard fields
entry_point = struct.unpack_from('<I', data, opt_off + 16)[0]
image_base = struct.unpack_from('<Q' if magic == 0x20B else '<I', data, opt_off + 24)[0]
section_align = struct.unpack_from('<I', data, opt_off + 32)[0]
file_align = struct.unpack_from('<I', data, opt_off + 36)[0]
size_of_image = struct.unpack_from('<I', data, opt_off + 56)[0]

print(f"Entry point: 0x{entry_point:X}")
print(f"Image base: 0x{image_base:X}")
print(f"Section alignment: 0x{section_align:X}")
print(f"File alignment: 0x{file_align:X}")
print(f"SizeOfImage: 0x{size_of_image:X}")

# Data directories
num_dirs = struct.unpack_from('<I', data, opt_off + (0x88 if magic == 0x20B else 0x70))[0]
print(f"Data directories: {num_dirs}")

dd_off = opt_off + 0x60
names = ['Export','Import','Resource','Exception','Security','Baseline','Reloc','Debug',
         'Architecture','GlobalPtr','TLSD','LoaderConfig','BoundImport','ImportAddr','DelayImport','COMDesc']
print("\nData directories:")
for i in range(min(num_dirs, 16)):
    rva, sz = struct.unpack_from('<II', data, dd_off + i*8)
    print(f"  [{i:2d}] {names[i]:15s}: RVA=0x{rva:08X} Size=0x{sz:X}")

# Parse sections properly
sec_off = opt_off + opt_size
print(f"\nSections (start at 0x{sec_off:X}):")
sections = []
for i in range(num_sec):
    name = data[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', 'replace')
    vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, sec_off+8)
    chara = struct.unpack_from('<I', data, sec_off+32)[0]
    num_rva = struct.unpack_from('<I', data, sec_off+36)[0]
    
    sections.append({
        'name': name, 'vaddr': vaddr, 'vsize': vsize,
        'raddr': raddr, 'rsize': rsize, 'chara': chara
    })
    
    print(f"  [{i:2d}] {name:8s} vaddr=0x{vaddr:08X} vsize=0x{vsize:08X} raddr=0x{raddr:08X} rsize=0x{rsize:08X}")
    sec_off += 40

# Find the actual .text section with reasonable size
print("\n=== Finding code sections ===")
for sec in sections:
    if sec['name'] in ('.text', '.code', '__text'):
        print(f"Code section '{sec['name']}':")
        print(f"  RVA: 0x{sec['vaddr']:X}, Size: 0x{sec['rsize']:X} ({sec['rsize']/1024:.0f} KB)")
        # Check if our target offsets fall in this section
        for name, off in [('ChatScreen', 0x108df707), ('Command', 0xe06ce81), ('TextPacket', 0xe133b84)]:
            if sec['raddr'] <= off < sec['raddr'] + sec['rsize']:
                rva = sec['vaddr'] + (off - sec['raddr'])
                print(f"  {name} (0x{off:X}) -> RVA 0x{rva:X} ✓")
            else:
                print(f"  {name} (0x{off:X}) NOT in this section")

# Also check .rdata for string data
print("\n=== String data sections ===")
for sec in sections:
    if sec['name'] in ('.rdata', '.data', '.rodata'):
        print(f"Data section '{sec['name']}':")
        print(f"  RVA: 0x{sec['vaddr']:X}, Size: 0x{sec['rsize']:X}")
        for name, off in [('ChatScreen', 0x108df707), ('Command', 0xe06ce81), ('TextPacket', 0xe133b84), ('PacketType', 0xe103b57)]:
            if sec['raddr'] <= off < sec['raddr'] + sec['rsize']:
                rva = sec['vaddr'] + (off - sec['raddr'])
                print(f"  {name} (0x{off:X}) -> RVA 0x{rva:X} ✓")
