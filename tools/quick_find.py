import struct, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

data = open(r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe','rb').read()

# Strategy: Find the vtable for Command class
# The RTTI string "virtual void __cdecl TakePictureCommand::execute" tells us
# the Command::execute vtable entry position
# Look for the pattern near this string

target_str = b'TakePictureCommand::execute'
idx = data.find(target_str)
if idx < 0:
    print('String not found')
    sys.exit(1)

print(f'TakePictureCommand::execute at file offset 0x{idx:X}')

# The string is in .rdata. Find its RVA
# .rdata: file 0xDA8A000, RVA 0xDA8B000
str_rva = 0xDA8B000 + (idx - 0xDA8A000)
print(f'String RVA: 0x{str_rva:X}')

# Now search .text for CALL instructions that target near this RVA
# These are likely calls through the vtable or direct calls to execute
print('\nSearching .text for CALLs near string RVA...')
text_start = 0x400
text_end = 0xDA8A000
text_rva_start = 0x1000

hits = []
for i in range(text_start, text_end - 4):
    if data[i] == 0xE8:
        disp = struct.unpack_from('<I', data, i+1)[0]
        call_rva = text_rva_start + (i - text_start)
        target_rva = call_rva + 5 + disp
        if abs(target_rva - str_rva) < 0x2000:
            hits.append((call_rva, target_rva))

print(f'Found {len(hits)} CALL instructions in range:')
for addr, target in sorted(hits)[:20]:
    print(f'  CALL at 0x{addr:X} -> 0x{target:X}')

# Also look for vtable reference patterns
# In x64, vtable access is typically: lea rax, [some_base + offset] followed by call [rax + offset]
# Or: mov rax, [rip + vtable_ptr] then call [rax + offset]
print('\nSearching for vtable access patterns near the string...')
for i in range(max(0, idx-0x200), min(len(data), idx+0x200)):
    chunk = data[i:i+8]
    # mov rax, [rip + disp32] - loading vtable pointer
    if chunk[0] == 0x48 and chunk[1] == 0x8B and chunk[2] == 0x05:
        disp = struct.unpack_from('<I', chunk, 3)[0]
        addr_rva = 0xDA8B000 + (i - 0xDA8A000)
        target = addr_rva + 7 + disp
        if abs(target - str_rva) < 0x1000:
            print(f'  mov rax,[rip+0x{disp:X}] at rdata+0x{i-0xDA8A000:X} -> 0x{target:X}')

# Find the Command vtable by looking for the RTTI type info
# The mangled name pattern is: ?execute@Command@@UEBAXAEBVCommandOrigin@@AEAVCommandOutput@@@Z
cmd_vtable_str = b'?execute@Command@@UEBAXAEBVCommandOrigin@@AEAVCommandOutput@@@Z'
idx2 = data.find(cmd_vtable_str)
if idx2 >= 0:
    cmd_rva = 0xDA8B000 + (idx2 - 0xDA8A000)
    print(f'\nCommand::execute vtable symbol at: 0x{cmd_rva:X}')
    # Search for references to this
    for i in range(text_start, text_end - 4):
        if data[i] == 0xE8:
            disp = struct.unpack_from('<I', data, i+1)[0]
            call_rva = text_rva_start + (i - text_start)
            target_rva = call_rva + 5 + disp
            if abs(target_rva - cmd_rva) < 0x100:
                print(f'  CALL to Command::execute at text RVA 0x{call_rva:X}')
else:
    # Try partial match
    partial = b'?execute@Command@@'
    idx3 = data.find(partial)
    if idx3 >= 0:
        print(f'\nPartial Command::execute symbol at: 0x{idx3:X}')

# Search for TextPacketPayload deserialize
print('\n=== TextPacketPayload deserialization ===')
tp_str = b'TextPacketPayload'
tp_idx = data.find(tp_str)
if tp_idx >= 0:
    tp_rva = 0xDA8B000 + (tp_idx - 0xDA8A000)
    print(f'TextPacketPayload at RVA 0x{tp_rva:X}')
    # Find deserialize/serialize methods
    for pattern in [b'?deserialize@TextPacketPayload', b'?serialize@TextPacketPayload']:
        pidx = data.find(pattern)
        if pidx >= 0:
            prva = 0xDA8B000 + (pidx - 0xDA8A000)
            print(f'  {pattern.decode()} at RVA 0x{prva:X}')

# Find PacketId enum (used to dispatch packets)
print('\n=== Packet dispatch ===')
pid_str = b'MinecraftPacketIds'
pid_idx = data.find(pid_str)
if pid_idx >= 0:
    pid_rva = 0xDA8B000 + (pid_idx - 0xDA8A000)
    print(f'MinecraftPacketIds at RVA 0x{pid_rva:X}')
    # The array of packet IDs is likely near this string
    # Read the array (usually DWORDs)
    arr_start = pid_idx + len(b'MinecraftPacketIds') + 1
    # Find next null
    arr_end = data.find(b'\x00', arr_start)
    if arr_end > arr_start:
        arr_data = data[arr_start:arr_end]
        # Parse as DWORD array
        num_entries = len(arr_data) // 4
        print(f'  Array: {num_entries} entries')
        ids = []
        for j in range(min(num_entries, 20)):
            val = struct.unpack_from('<I', arr_data, j*4)[0]
            ids.append(val)
        print(f'  First 20 IDs: {ids}')
