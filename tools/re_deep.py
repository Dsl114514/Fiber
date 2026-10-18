#!/usr/bin/env python3
"""Deep function boundary analysis for chat hook points."""
import struct, sys, io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
data = open(path, 'rb').read()

def off_to_rva(off):
    if 0x400 <= off < 0xDA8A000: return 0x1000 + (off - 0x400)
    if 0xDA8A000 <= off < 0x10A99600: return 0xDA8B000 + (off - 0xDA8A000)
    if 0x10799600 <= off < 0x10C4DC00: return 0x1079B000 + (off - 0x10799600)
    return -1

def rva_to_off(rva):
    if 0x1000 <= rva < 0xDA8AC00: return 0x400 + (rva - 0x1000)
    if 0xDA8B000 <= rva < 0x10A9A600: return 0xDA8A000 + (rva - 0xDA8B000)
    if 0x1079B000 <= rva < 0x10C4DC00: return 0x10799600 + (rva - 0x1079B000)
    return -1

text_start = 0x400
text_end = 0xDA8A000
text_rva_start = 0x1000

def find_func_start(addr_rva, max_back=0x1000):
    """Scan backwards for function start (look for RET or prologue)."""
    file_off = rva_to_off(addr_rva)
    if file_off < 0: return -1
    for back in range(0, min(max_back, file_off - text_start), 4):
        addr = file_off - back
        chunk = data[addr:addr+4]
        if len(chunk) < 2: continue
        # Check for RET (C3) - potential function end
        if chunk[0] == 0xC3:
            # Check previous bytes for typical epilogue
            if addr > file_off - 20:
                continue
            # Look for PUSH before RET (function prologue end)
            for p in range(1, min(16, addr - file_off)):
                if data[addr-p] in (0x50|0, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,
                                     0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47):
                    return addr_rva - back + p
            if addr > file_off - 4 and data[addr-1:addr] == b'\xC9':  # LEAVE; RET
                return addr_rva - back + 1
    # Also check for SUB RSP, imm8 (48 83 EC imm) - classic x64 prologue
    for back in range(0, min(max_back, file_off - text_start), 1):
        addr = file_off - back
        if addr + 3 > len(data): continue
        chunk = data[addr:addr+4]
        if len(chunk) >= 3 and chunk[0] == 0x48 and chunk[1] == 0x83 and chunk[2] == 0xEC:
            return addr_rva - back
    return addr_rva

def find_func_end(addr_rva, max_forward=0x1000):
    """Scan forward for function end (RET instruction)."""
    file_off = rva_to_off(addr_rva)
    if file_off < 0: return -1
    end = min(file_off + max_forward, text_end)
    for i in range(file_off, end - 1):
        if data[i] == 0xC3:
            # Check if this looks like end of function
            if i > file_off + 4:
                return addr_rva + (i - file_off)
    return -1

def get_function_bytes(addr_rva, size):
    """Read bytes from a function."""
    file_off = rva_to_off(addr_rva)
    if file_off < 0: return b''
    return data[file_off:file_off+size]

def find_vtable_for_class(class_rtti_offset):
    """Find vtable references near an RTTI string."""
    rva = off_to_rva(class_rtti_offset)
    if rva < 0: return []
    results = []
    for i in range(text_start, text_end - 8):
        if data[i] == 0xE8:
            disp = struct.unpack_from('<I', data, i+1)[0]
            call_rva = text_rva_start + (i - text_start)
            target = call_rva + 5 + disp
            if abs(target - rva) < 0x500:
                results.append((call_rva, target))
    return results

print("=" * 80)
print("DEEP FUNCTION ANALYSIS")
print("=" * 80)

# ── Target 1: Command::execute ──────────────────────────────────────────────
print("\n[Target 1] Command::execute")

# Find the virtual function declaration string
cmd_vtbl_str = b'virtual void __cdecl TakePictureCommand::execute(const CommandOrigin &, CommandOutput &) const'
h = data.find(cmd_vtbl_str)
if h >= 0:
    rva = off_to_rva(h)
    print(f"  Virtual function string at: file=0x{h:X} RVA=0x{rva:X}")
    # Find CALLs to nearby code
    refs = find_vtable_for_class(h)
    print(f"  Nearby CALLs: {len(refs)}")
    for call_rva, target_rva in refs[:5]:
        func_start = find_func_start(call_rva)
        func_end = find_func_end(call_rva)
        print(f"    CALL 0x{call_rva:X} -> 0x{target_rva:X} (func: 0x{func_start:X}-0x{func_end:X})")

# Also search for the Command class RTTI
cmd_rtti = b'Command@@7'
h2 = data.find(cmd_rtti)
if h2 >= 0:
    rva2 = off_to_rva(h2)
    print(f"  Command RTTI: file=0x{h2:X} RVA=0x{rva2:X}")
    refs2 = find_vtable_for_class(h2)
    print(f"  Nearby CALLs: {len(refs2)}")
    for call_rva, target_rva in refs2[:5]:
        print(f"    CALL 0x{call_rva:X} -> 0x{target_rva:X}")

# ── Target 2: TextPacketPayload deserialize ─────────────────────────────────
print("\n[Target 2] TextPacketPayload deserialize")
for pat in [b'?deserialize@TextPacketPayload', b'?serialize@TextPacketPayload',
            b'cereal::BasicLoader::load', b'TextPacketPayload::MessageOnly']:
    h = data.find(pat)
    if h >= 0:
        rva = off_to_rva(h)
        print(f"  {pat.decode()}: RVA 0x{rva:X}")
        # Find calls to nearby
        refs = find_vtable_for_class(h)
        for call_rva, target_rva in refs[:5]:
            print(f"    CALL 0x{call_rva:X} -> 0x{target_rva:X}")

# ── Target 3: Packet dispatch table ─────────────────────────────────────────
print("\n[Target 3] Packet dispatch")
pid_off = data.find(b'MinecraftPacketIds')
if pid_off >= 0:
    pid_rva = off_to_rva(pid_off)
    print(f"  MinecraftPacketIds: RVA 0x{pid_rva:X}")
    # The array is 256 DWORDs after the string
    arr_off = pid_off + len(b'MinecraftPacketIds') + 1
    # Find the actual packet ID values (they should be small integers, not large hashes)
    # Look for a pattern of small sequential values
    for start in range(0, 0x100):
        vals = []
        for i in range(32):
            val = struct.unpack_from('<I', data, arr_off + start + i*4)[0]
            if val > 256: break
            vals.append(val)
        if len(vals) >= 8:
            print(f"  Potential packet IDs at offset +{start}: {vals}")
            break

# ── Target 4: NetworkHandler packet dispatch ────────────────────────────────
print("\n[Target 4] Network handler dispatch")
snh_off = data.find(b'ServerNetworkHandler')
if snh_off >= 0:
    snh_rva = off_to_rva(snh_off)
    print(f"  ServerNetworkHandler: RVA 0x{snh_rva:X}")
    # Find the function that contains this string
    func_start = find_func_start(snh_rva)
    func_end = find_func_end(snh_rva)
    print(f"  Function: 0x{func_start:X} - 0x{func_end:X}")

    # Also look for the packet handler array
    # It's typically near the NetworkHandler class
    for pat in [b'handlePacket', b'PacketHandler', b'NetworkHandler']:
        h = data.find(pat, snh_off - 0x10000 if snh_off > 0x10000 else 0)
        if h >= 0 and h < snh_off + 0x10000:
            rva = off_to_rva(h)
            print(f"  {pat.decode()}: RVA 0x{rva:X}")

# ── Target 5: Chat filter / moderation ───────────────────────────────────────
print("\n[Target 5] Chat filter")
filter_off = data.find(b'TextFilter')
if filter_off >= 0:
    filter_rva = off_to_rva(filter_off)
    print(f"  TextFilter: RVA 0x{filter_rva:X}")
    # Find nearby function
    func_start = find_func_start(filter_rva)
    print(f"  Function start: 0x{func_start:X}")

# ── Target 6: Look for the actual command execution path ────────────────────
print("\n[Target 6] Command execution path")
# Search for "commands." namespace strings which indicate command registration
cmd_ns = b'commands.'
hits = find_all(cmd_ns, 20)
print(f"  Found {len(hits)} 'commands.' strings")
for h in hits[:10]:
    rva = off_to_rva(h)
    ctx = data[max(0,h-50):h+100]
    text = ctx.decode('ascii', errors='replace')
    for s in text.split('\x00'):
        if 'command' in s.lower() or len(s) > 10:
            print(f"    0x{h:X}: {s[:80]}")
            break

# ── Target 7: Find tell/say command handlers ────────────────────────────────
print("\n[Target 7] Tell/Say commands")
for pat in [b'tellraw', b'SayCommand', b'TellCommand', b'?execute@SayCommand',
            b'?execute@TellCommand', b'?execute@TeamCommand']:
    h = data.find(pat)
    if h >= 0:
        rva = off_to_rva(h)
        print(f"  {pat.decode()}: RVA 0x{rva:X}")
        func_start = find_func_start(rva)
        print(f"    Function start: 0x{func_start:X}")

print("\n" + "=" * 80)
print("Searching for the packet receive/dispatch function...")
print("=" * 80)

# Search for the network receive loop
# Look for recv() or receive() patterns
for pat in [b'network::receive', b'?receive@', b'?recv@', b'Socket::receive',
            b'NetworkQueue', b'NetworkLayer']:
    h = data.find(pat)
    if h >= 0:
        rva = off_to_rva(h)
        print(f"  {pat.decode()}: RVA 0x{rva:X}")
        func_start = find_func_start(rva)
        func_end = find_func_end(rva)
        print(f"    Function: 0x{func_start:X} - 0x{func_end:X}")
        # Show bytes around this function
        if func_start > 0:
            foff = rva_to_off(func_start)
            if foff >= 0:
                func_bytes = data[foff:foff+64]
                print(f"    First bytes: {func_bytes[:32].hex()}")
