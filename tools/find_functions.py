#!/usr/bin/env python3
"""Find function addresses that reference key RTTI strings."""
import struct
import sys
import io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
data = open(path, 'rb').read()

# Section mapping (file offset -> RVA)
def file_to_rva(off):
    # .text: file 0x400-0xDA8A000, RVA 0x1000
    if 0x400 <= off < 0xDA8A000:
        return 0x1000 + (off - 0x400)
    # .rdata: file 0xDA8A000-0x10A99600, RVA 0xDA8B000
    if 0xDA8A000 <= off < 0x10A99600:
        return 0xDA8B000 + (off - 0xDA8A000)
    # .data: file 0x10799600-0x10C4DC00, RVA 0x1079B000
    if 0x10799600 <= off < 0x10C4DC00:
        return 0x1079B000 + (off - 0x10799600)
    # .pdata: file 0x10C4DC00-..., RVA 0x10F5C000
    if 0x10C4DC00 <= off < 0x1161D200:
        return 0x10F5C000 + (off - 0x10C4DC00)
    return -1

# Key strings to find
targets = [
    ('ChatScreenController', 0x108DF707),
    ('Command::execute vtable', 0xE06CE81),
    ('TextPacketPayload', 0xE133B84),
    ('TextPacketPayload::MessageOnly', 0xE14A7C8),
    ('PacketType enum', 0xE103B57),
    ('FilterTextPacket', 0xE07FBB2),
]

print("=== Finding code references to target strings ===\n")

for name, file_off in targets:
    rva = file_to_rva(file_off)
    if rva < 0:
        print(f"{name}: file=0x{file_off:X} NOT IN KNOWN SECTIONS")
        continue

    print(f"【{name}】")
    print(f"  String at file=0x{file_off:X}, RVA=0x{rva:X}")

    # Search .text section for LEA/RIP-rel references to this RVA
    # x64 LEA: 48 8D 05 <disp32> where target = [rip+7+disp32]
    # We look for patterns that reference our target RVA

    text_start = 0x400
    text_end = 0xDA8A000
    text_rva_start = 0x1000
    text_rva_end = 0xDA8AC00

    # Target dispersion value for LEA
    # If instruction is at text_rva X, then disp32 = target_rva - (X + 7)
    # So X = target_rva - disp32 - 7

    # Search for the target RVA as a direct reference in call targets
    # Look for E8 XX XX XX XX (call rel32) where target matches
    found_calls = []
    found_leas = []

    for i in range(text_start, text_end - 8, 4):
        chunk = data[i:i+8]
        # call rel32: E8 <disp32>
        if chunk[0] == 0xE8:
            disp = struct.unpack_from('<I', chunk, 1)[0]
            target_rva = text_rva_start + (i - text_start) + 5 + disp
            if abs(target_rva - rva) < 0x100:
                found_calls.append((text_rva_start + (i - text_start), target_rva))
        # lea rax, [rip+disp32]: 48 8D 05 <disp32>
        elif chunk[0:3] == b'\x48\x8D\x05':
            disp = struct.unpack_from('<I', chunk, 3)[0]
            instr_rva = text_rva_start + (i - text_start)
            target_rva = instr_rva + 7 + disp
            if abs(target_rva - rva) < 0x100:
                found_leas.append((instr_rva, target_rva))

    if found_calls:
        print(f"  Calls near target ({len(found_calls)} found):")
        for addr, target in found_calls[:10]:
            print(f"    Call at RVA 0x{addr:X} -> 0x{target:X}")

    if found_leas:
        print(f"  LEA references near target ({len(found_leas)} found):")
        for addr, target in found_leas[:10]:
            print(f"    LEA at RVA 0x{addr:X} -> 0x{target:X}")

    # Also scan for the string bytes directly in .text
    # This finds inline string references
    str_bytes = data[file_off:file_off+20]
    if len(str_bytes) > 0:
        # Look for the string's first few bytes in .text (unusual but possible)
        pass

    print()

# Now analyze the area around each target to find function boundaries
print("\n=== Analyzing function prologues near targets ===\n")

for name, file_off in targets[:3]:  # First 3 targets
    rva = file_to_rva(file_off)
    if rva < 0:
        continue

    print(f"【{name}】RVA=0x{rva:X}")

    # Search backwards from the string reference for function prologue
    # Look for typical x64 prologues in .text
    text_start = 0x400
    text_end = 0xDA8A000

    # Find the nearest code reference to this string
    best_addr = None
    best_dist = 0x10000

    for i in range(text_start, text_end - 8):
        chunk = data[i:i+8]
        # lea rax, [rip+disp]
        if chunk[0:3] == b'\x48\x8D\x05':
            disp = struct.unpack_from('<I', chunk, 3)[0]
            instr_rva = 0x1000 + (i - text_start)
            target_rva = instr_rva + 7 + disp
            if abs(target_rva - rva) < best_dist:
                best_dist = abs(target_rva - rva)
                best_addr = 0x1000 + (i - text_start)

    if best_addr:
        print(f"  Nearest LEA at RVA 0x{best_addr:X} (dist=0x{best_dist:X})")

        # Scan backwards for function start
        # Look for RET or function prologue
        for back in range(0, 0x500):
            addr = best_addr - back
            if addr < 0x1000:
                break
            file_addr = text_start + (addr - 0x1000)
            chunk = data[file_addr:file_addr+4]

            # Check for RET (C3)
            if chunk[0] == 0xC3:
                # Check if this is a standalone ret (end of previous function)
                if back > 2:
                    prev = data[file_addr-3:file_addr]
                    if prev == b'\xC9\xC3' or prev == b'\x48\xC3':
                        func_end = addr
                        print(f"  Function end at RVA 0x{func_end:X}")
                        break

            # Check for push rax (50) or sub rsp, imm (48 83 EC imm)
            if chunk[0] == 0x48 and chunk[1] == 0x83 and chunk[2] == 0xEC:
                # sub rsp, imm8
                func_start = addr
                print(f"  Function start at RVA 0x{func_start:X} (sub rsp, ...)")
                break
            elif chunk[0] in (0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57):
                # push rax-r15
                func_start = addr
                print(f"  Potential function start at RVA 0x{func_start:X} (push {hex(chunk[0])})")

    print()
