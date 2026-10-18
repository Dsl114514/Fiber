#!/usr/bin/env python3
"""Find Chat/Command hook points in Minecraft.Windows.exe."""
import struct, sys, io

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
data = open(path, 'rb').read()

# Section mapping
def off_to_rva(off):
    if 0x400 <= off < 0xDA8A000: return 0x1000 + (off - 0x400)
    if 0xDA8A000 <= off < 0x10A99600: return 0xDA8B000 + (off - 0xDA8A000)
    if 0x10799600 <= off < 0x10C4DC00: return 0x1079B000 + (off - 0x10799600)
    return -1

# Find all occurrences of a pattern
def find_all(pattern, limit=0):
    results = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx < 0 or idx > 0x20000000: break
        results.append(idx)
        start = idx + 1
        if limit and len(results) >= limit: break
    return results

print("=" * 80)
print("FIBER REVERSE ENGINEERING - Chat Hook Point Localization")
print("=" * 80)

# ── 1. Command::execute vtable ──────────────────────────────────────────────
print("\n[1] Command::execute vtable")
# The vtable string pattern: "?execute@Command@@UEBAXAEBVCommandOrigin@@AEAVCommandOutput@@@Z"
cmd_execute_mangled = b'?execute@Command@@UEBAXAEBVCommandOrigin@@AEAVCommandOutput@@@Z'
hits = find_all(cmd_execute_mangled, 5)
for h in hits:
    rva = off_to_rva(h)
    print(f"  Symbol: 0x{h:X} -> RVA 0x{rva:X}")
    # Show context
    ctx = data[max(0,h-100):h+200]
    try:
        text = ctx.decode('ascii', errors='replace')
    except:
        text = ctx.hex()
    for s in text.split('\x00'):
        if len(s) > 5 and ('Command' in s or 'execute' in s.lower()):
            print(f"    >>> {s[:120]}")

# Also look for the vtable symbol itself
vtable_pat = b'?vtable for Command@'
hits2 = find_all(vtable_pat, 3)
for h in hits2:
    rva = off_to_rva(h)
    print(f"  VTable symbol: 0x{h:X} -> RVA 0x{rva:X}")

# ── 2. TextPacketPayload ────────────────────────────────────────────────────
print("\n[2] TextPacketPayload")
text_pkt = b'TextPacketPayload'
hits = find_all(text_pkt, 10)
for h in hits[:5]:
    rva = off_to_rva(h)
    # Show what's around it
    ctx = data[max(0,h-80):h+200]
    text = ctx.decode('ascii', errors='replace')
    for s in text.split('\x00'):
        if len(s) > 3:
            print(f"  0x{h-X if False else h:X}: {s[:120]}")
            break

# Look for deserialize/serialize
for pat in [b'?deserialize@TextPacketPayload', b'?serialize@TextPacketPayload',
            b'?handle@TextPacketPayload', b'__cdecl TextPacketPayload']:
    h = data.find(pat)
    if h >= 0:
        rva = off_to_rva(h)
        print(f"  {pat.decode()}: RVA 0x{rva:X}")
        ctx = data[max(0,h-100):h+200]
        text = ctx.decode('ascii', errors='replace')
        for s in text.split('\x00'):
            if 'TextPacket' in s or 'deserialize' in s or 'serialize' in s:
                print(f"    >>> {s[:150]}")

# ── 3. Packet dispatch (MinecraftPacketIds) ─────────────────────────────────
print("\n[3] Packet dispatch table")
pid_str = b'MinecraftPacketIds'
h = data.find(pid_str)
if h >= 0:
    rva = off_to_rva(h)
    print(f"  MinecraftPacketIds string at RVA 0x{rva:X}")
    # The array is typically right after the string
    arr_off = h + len(pid_str) + 1
    ids = []
    for i in range(256):
        val = struct.unpack_from('<I', data, arr_off + i*4)[0]
        if val == 0: break
        ids.append(val)
    print(f"  Array: {len(ids)} entries")
    # These are likely hash values, not packet IDs. Let's look for the actual
    # packet ID enum or dispatch table

# ── 4. Chat-related class methods ────────────────────────────────────────────
print("\n[4] Chat subsystem classes")
chat_classes = [
    b'ChatSession',
    b'ChatSubsystem',
    b'ServerChatSession',
    b'ClientChatSession',
    b'?handleTextPacket',
    b'?onTextPacket',
    b'?sendChatMessage',
    b'?handleChatMessage',
    b'?processChatMessage',
    b'ChatMessage',
    b'FilterTextPacket',
    b'?deserialize@FilterTextPacket',
]
for pat in chat_classes:
    hits = find_all(pat, 3)
    for h in hits:
        rva = off_to_rva(h)
        ctx = data[max(0,h-60):h+len(pat)+100]
        text = ctx.decode('ascii', errors='replace')
        for s in text.split('\x00'):
            if len(s) > 5:
                print(f"  {pat.decode()}: RVA 0x{rva:X} | {s[:100]}")
                break

# ── 5. Network handler packet dispatch ──────────────────────────────────────
print("\n[5] Network packet dispatch")
net_patterns = [
    b'NetworkHandler::handlePacket',
    b'?handlePacket@NetworkHandler',
    b'?handlePacket@ServerNetworkHandler',
    b'?handlePacket@ClientNetworkHandler',
    b'ServerNetworkHandler::handlePacket',
    b'handlePacket',
]
for pat in net_patterns:
    hits = find_all(pat, 3)
    for h in hits:
        rva = off_to_rva(h)
        ctx = data[max(0,h-100):h+200]
        text = ctx.decode('ascii', errors='replace')
        for s in text.split('\x00'):
            if len(s) > 5 and ('Packet' in s or 'handle' in s.lower() or 'Network' in s):
                print(f"  {pat.decode()}: RVA 0x{rva:X} | {s[:120]}")
                break

# ── 6. Find function that contains chat string references ───────────────────
print("\n[6] Functions referencing chat strings (RVA-based search)")
# Look for LEA instructions near the ChatScreenController string that might
# be the function that creates/initializes it
chat_screen_off = 0x108DF707
chat_screen_rva = off_to_rva(chat_screen_off)
print(f"  ChatScreenController string: file=0x{chat_screen_off:X} RVA=0x{chat_screen_rva:X}")

# Search .text for LEA instructions referencing this RVA
# LEA: 48 8D 05 <disp32>, target = [rip+7+disp32]
text_start = 0x400
text_end = 0xDA8A000
text_rva_start = 0x1000

nearby_calls = []
for i in range(text_start, text_end - 8):
    if data[i] == 0xE8:  # call rel32
        disp = struct.unpack_from('<I', data, i+1)[0]
        call_rva = text_rva_start + (i - text_start)
        target = call_rva + 5 + disp
        if abs(target - chat_screen_rva) < 0x5000:
            nearby_calls.append((call_rva, target))

print(f"  CALLs within 0x5000 of ChatScreenController: {len(nearby_calls)}")
for addr, target in sorted(nearby_calls)[:10]:
    print(f"    CALL at 0x{addr:X} -> 0x{target:X}")

# ── 7. Look for the packet handler table in ServerNetworkHandler ────────────
print("\n[7] ServerNetworkHandler packet dispatch")
snh_off = 0xE07E29A  # from earlier analysis
snh_rva = off_to_rva(snh_off)
print(f"  ServerNetworkHandler string: RVA 0x{snh_rva:X}")

# Search for references near this address
for i in range(text_start, text_end - 8):
    if data[i] == 0xE8:
        disp = struct.unpack_from('<I', data, i+1)[0]
        call_rva = text_rva_start + (i - text_start)
        target = call_rva + 5 + disp
        if abs(target - snh_rva) < 0x3000:
            print(f"    CALL at 0x{call_rva:X} -> 0x{target:X}")

# ── 8. Search for the command handler dispatch ──────────────────────────────
print("\n[8] Command dispatch")
cmd_reg_off = 0xE05C1A4  # CommandRegistry
cmd_reg_rva = off_to_rva(cmd_reg_off)
print(f"  CommandRegistry string: RVA 0x{cmd_reg_rva:X}")

for i in range(text_start, text_end - 8):
    if data[i] == 0xE8:
        disp = struct.unpack_from('<I', data, i+1)[0]
        call_rva = text_rva_start + (i - text_start)
        target = call_rva + 5 + disp
        if abs(target - cmd_reg_rva) < 0x3000:
            print(f"    CALL at 0x{call_rva:X} -> 0x{target:X}")

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
