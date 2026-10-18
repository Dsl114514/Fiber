import struct, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

data = open(r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe','rb').read()

def rva_to_file(rva):
    if 0x1000 <= rva < 0xDA8AC00:  # .text
        return 0x400 + (rva - 0x1000)
    if 0xDA8B000 <= rva < 0x10A9A600:  # .rdata
        return 0xDA8A000 + (rva - 0xDA8B000)
    if 0x1079B000 <= rva < 0x10C4DC00:  # .data
        return 0x10799600 + (rva - 0x1079B000)
    return -1

def file_to_rva(file_off):
    if 0x400 <= file_off < 0xDA8A000:
        return 0x1000 + (file_off - 0x400)
    if 0xDA8A000 <= file_off < 0x10A99600:
        return 0xDA8B000 + (file_off - 0xDA8A000)
    if 0x10799600 <= file_off < 0x10C4DC00:
        return 0x1079B000 + (file_off - 0x10799600)
    return -1

# 1. Find Command::execute vtable symbol
print("=== Command::execute analysis ===")
# The mangled name for Command::execute
targets = [
    (b'?execute@Command@@UEBAXAEBVCommandOrigin@@AEAVCommandOutput@@@Z', 'Command::execute full'),
    (b'?execute@Command@@', 'Command::execute partial'),
    (b'Command::execute', 'Command::execute simple'),
]

for pat, desc in targets:
    idx = data.find(pat)
    if idx >= 0:
        rva = file_to_rva(idx)
        print(f'{desc}: file=0x{idx:X} RVA=0x{rva:X}')
        # Show context
        ctx = data[max(0,idx-50):idx+len(pat)+100]
        try:
            text = ctx.decode('ascii', errors='replace')
        except:
            text = ctx.hex()
        print(f'  Context: {text[:150]}')

# 2. Find the actual function prologue for Command::execute
# Look for the vtable entry - typically at a known offset from the class start
# The string "virtual void __cdecl TakePictureCommand::execute" references the base class vtable
print("\n=== Finding Command vtable ===")
vp_str = b'virtual void __cdecl TakePictureCommand::execute(const CommandOrigin &, CommandOutput &) const'
idx = data.find(vp_str)
if idx >= 0:
    vp_rva = file_to_rva(idx)
    print(f'Vertc str at RVA 0x{vp_rva:X}')
    # The vtable for Command class should be near here
    # Search backwards for the vtable pointer
    # Typically: .data segment has the vtable, referenced by .text
    # Look for the mangled vtable name
    vtable_pat = b'?vtable for Command@@ 12'
    idx2 = data.find(vtable_pat)
    if idx2 < 0:
        vtable_pat = b'?vtable for Command@'
        idx2 = data.find(vtable_pat)
    if idx2 < 0:
        vtable_pat = b'Command@@7'
        idx2 = data.find(vtable_pat)
    if idx2 >= 0:
        vt_rva = file_to_rva(idx2)
        print(f'Command vtable symbol at RVA 0x{vt_rva:X}')

# 3. Find TextPacketPayload deserialize
print("\n=== TextPacketPayload analysis ===")
tp_targets = [
    b'?deserialize@TextPacketPayload',
    b'?serialize@TextPacketPayload',
    b'?handle@TextPacketPayload',
]
for pat in tp_targets:
    idx = data.find(pat)
    if idx >= 0:
        rva = file_to_rva(idx)
        print(f'{pat.decode()}: RVA=0x{rva:X}')

# 4. Find the packet dispatch table
print("\n=== Packet dispatch analysis ===")
# MinecraftPacketIds array
pid_idx = data.find(b'MinecraftPacketIds')
if pid_idx >= 0:
    pid_rva = file_to_rva(pid_idx)
    print(f'MinecraftPacketIds at RVA 0x{pid_rva:X}')
    # The array is typically right after the name string
    arr_off = pid_idx + len(b'MinecraftPacketIds') + 1
    # Read DWORD values
    ids = []
    for i in range(256):
        val = struct.unpack_from('<I', data, arr_off + i*4)[0]
        if val == 0:
            break
        ids.append(val)
    print(f'Packet IDs (first {len(ids)}): {ids[:30]}')

# 5. Find the network handler packet dispatch
print("\n=== Network handler dispatch ===")
dispatch_targets = [
    b'handlePacket',
    b'HandlePacket',
    b'?handlePacket@',
    b'NetworkHandler::',
]
for pat in dispatch_targets:
    idx = data.find(pat)
    if idx >= 0:
        rva = file_to_rva(idx)
        print(f'{pat.decode()}: RVA=0x{rva:X}')
        # Show context
        ctx = data[max(0,idx-30):idx+len(pat)+80]
        text = ctx.decode('ascii', errors='replace')
        print(f'  {text[:100]}')

# 6. Key insight: Find the packet handler array in ServerNetworkHandler
# This is typically an array of function pointers indexed by PacketId
print("\n=== Looking for packet handler table ===")
# Search for the pattern near ServerNetworkHandler
snh_str = b'ServerNetworkHandler'
idx = data.find(snh_str)
if idx >= 0:
    snh_rva = file_to_rva(idx)
    print(f'ServerNetworkHandler at RVA 0x{snh_rva:X}')
    # The handler table is likely in .data near this
    # Look for references to this in .text
    text_start = 0x400
    for i in range(text_start, 0xDA8A000 - 4):
        if data[i] == 0xE8:
            disp = struct.unpack_from('<I', data, i+1)[0]
            call_rva = 0x1000 + (i - text_start)
            target_rva = call_rva + 5 + disp
            if abs(target_rva - snh_rva) < 0x1000:
                print(f'  Reference at text RVA 0x{call_rva:X}')

print("\n=== Analysis complete ===")
print("Key findings:")
print("1. Command::execute vtable string at ~0xE06CE81")
print("2. TextPacketPayload at ~0xE133B84")
print("3. MinecraftPacketIds array at ~0xE09DA62")
print("4. Need to find: actual function entry points for hooking")
