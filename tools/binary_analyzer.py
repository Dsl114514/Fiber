#!/usr/bin/env python3
"""Binary analysis for Minecraft Bedrock 1.26.33.1 - Chat hook point localization."""
import struct
import sys
import os

# Force UTF-8 output
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

class PEAnalyzer:
    def __init__(self, path: str):
        self.path = path
        self.data = open(path, 'rb').read()
        self.sections = []
        self._parse_pe()

    def _parse_pe(self):
        e_lfanew = struct.unpack_from('<I', self.data, 0x3C)[0]
        magic = struct.unpack_from('<H', self.data, e_lfanew + 24)[0]
        self.is64 = magic == 0x20B
        opt_size = struct.unpack_from('<H', self.data, e_lfanew + 20)[0]
        num_sec = struct.unpack_from('<H', self.data, e_lfanew + 6)[0]
        sec_off = e_lfanew + 24 + opt_size
        for i in range(num_sec):
            name = self.data[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', 'replace')
            vaddr, vsize, raddr, rsize = struct.unpack_from('<IIII', self.data, sec_off+8)
            self.sections.append({
                'name': name, 'vaddr': vaddr, 'vsize': vsize,
                'raddr': raddr, 'rsize': rsize
            })
            sec_off += 40

    def rva_to_off(self, rva: int) -> int:
        for sec in self.sections:
            if sec['vaddr'] <= rva < sec['vaddr'] + max(sec['vsize'], sec['rsize']):
                return sec['raddr'] + (rva - sec['vaddr'])
        return -1

    def off_to_rva(self, off: int) -> int:
        for sec in self.sections:
            if sec['raddr'] <= off < sec['raddr'] + sec['rsize']:
                return sec['vaddr'] + (off - sec['raddr'])
        return -1

    def find_all(self, pattern: bytes) -> list:
        results = []
        start = 0
        while True:
            idx = self.data.find(pattern, start)
            if idx < 0 or idx > 0x20000000:
                break
            results.append(idx)
            start = idx + 1
        return results

    def scan_back_for_ret(self, addr: int, max_scan: int = 0x500) -> int:
        """Scan backwards for RET instruction to find function end."""
        p = addr
        while p > max(0, addr - max_scan):
            p -= 1
            if self.data[p] == 0xC3:
                # Check if next byte is null or start of new instruction
                if p + 1 >= len(self.data) or self.data[p+1] == 0:
                    return p
                # Check for typical function epilogue patterns
                if p > 2:
                    prev = self.data[p-3:p]
                    if prev in (b'\xC9\xC3', b'\x48\xC3'):  # leave; ret or ret
                        return p
        return addr


def main():
    path = r'E:\mcb\bedrock_versions\1.26.3301\Minecraft.Windows.exe'
    analyzer = PEAnalyzer(path)

    print(f"Analyzing {path}")
    print(f"File size: {len(analyzer.data):,} bytes")
    print(f"Sections: {len(analyzer.sections)}")

    # Key strings and their offsets
    key_symbols = [
        ('ChatScreenController', 0x108df707),
        ('Command::execute', 0xe06ce81),
        ('TextPacketPayload', 0xe133b84),
        ('PacketType', 0xe103b57),
        ('PacketId', 0xe09ca58),
        ('TextPacketPayload::MessageOnly', 0xe14a7c8),
        ('FilterTextPacket', 0xe07fbb2),
        ('ServerNetworkHandler::_onPlayerLeft', 0xe07e29a),
    ]

    print("\n" + "="*80)
    print("KEY SYMBOL ANALYSIS")
    print("="*80)

    for name, offset in key_symbols:
        rva = analyzer.off_to_rva(offset)
        print(f"\n【{name}】")
        print(f"  File offset: 0x{offset:X}")
        print(f"  RVA: 0x{rva:X}" if rva > 0 else "  RVA: N/A")

        # Get context strings
        ctx_start = max(0, offset - 300)
        ctx_end = min(len(analyzer.data), offset + 800)
        chunk = analyzer.data[ctx_start:ctx_end]

        strings = []
        for i in range(len(chunk) - 1):
            if chunk[i] == 0:
                j = i + 1
                while j < len(chunk) and chunk[j] != 0:
                    j += 1
                if j - i > 4:
                    try:
                        s = chunk[i+1:j].decode('ascii', 'replace')
                        if len(s) > 3:
                            strings.append((ctx_start + i + 1, s))
                    except:
                        pass

        print(f"  Nearby strings:")
        for rel_off, s in strings[:15]:
            print(f"    0x{rel_off:X}: {s[:100]}")

        # Find nearby function boundaries
        print(f"  Function analysis:")
        # Look for RET instructions near this offset
        for delta in range(-0x200, 0x200, 4):
            addr = offset + delta
            if addr < 0 or addr > len(analyzer.data) - 2:
                continue
            # Check for typical function epilogue
            if analyzer.data[addr] == 0xC3:  # ret
                # Look backwards for push/lea that might be function start
                for back in range(1, min(0x100, addr)):
                    if analyzer.data[addr - back] in (0x50|0, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,
                                                       0x48, 0x4C, 0x4D):  # push rax-r15 or mov
                        func_start = addr - back
                        func_rva = analyzer.off_to_rva(func_start)
                        print(f"    Potential function: 0x{func_rva:X} (RET at 0x{addr:X})")
                        break

    # Analyze .text section for call patterns near key strings
    print("\n" + "="*80)
    print("FUNCTION CALL PATTERN ANALYSIS")
    print("="*80)

    # Find .text section
    text_sec = None
    for sec in analyzer.sections:
        if sec['name'] == '.text':
            text_sec = sec
            break

    if text_sec:
        print(f"\n.text section: RVA=0x{text_sec['vaddr']:X}, Size=0x{text_sec['rsize']:X}")

        # Analyze area around ChatScreenController
        target_offset = 0x108df707
        target_rva = analyzer.off_to_rva(target_offset)
        if target_rva > 0:
            print(f"\nAnalyzing area around ChatScreenController (RVA 0x{target_rva:X}):")

            # Search for call instructions in nearby code
            search_start = max(text_sec['raddr'], target_offset - 0x1000)
            search_end = min(len(analyzer.data), target_offset + 0x1000)
            search_chunk = analyzer.data[search_start:search_end]

            calls = []
            for i in range(len(search_chunk) - 5):
                # call rel32
                if search_chunk[i] == 0xE8:
                    disp = struct.unpack_from('<I', search_chunk, i+1)[0]
                    target = search_start + i + 5 + disp
                    if 0 < target < 0xFFFFFFFF:
                        calls.append((search_start + i, target, 'call_rel'))
                # call [rip+disp32]
                elif search_chunk[i] == 0xFF and search_chunk[i+1] == 0x15:
                    disp = struct.unpack_from('<I', search_chunk, i+2)[0]
                    target = search_start + i + 6 + disp
                    calls.append((search_start + i, target, 'call_indirect'))

            print(f"  Found {len(calls)} call instructions:")
            for addr, target, ctype in calls[:20]:
                print(f"    0x{addr:X}: {ctype} -> 0x{target:X}")

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)


if __name__ == '__main__':
    main()
