#!/usr/bin/env python3
"""Persistent MCP client for IDA reverse engineering."""
import subprocess, json, time, sys, select

MCP_SERVER = r'C:\Python314\Lib\site-packages'
IDA_RPC = 'http://127.0.0.1:13337'

class MCPClient:
    def __init__(self):
        self.proc = None
        self.running = False

    def start(self):
        self.proc = subprocess.Popen(
            [sys.executable, '-m', 'ida_pro_mcp.server', '--ida-rpc', IDA_RPC],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=MCP_SERVER, creationflags=subprocess.CREATE_NO_WINDOW
        )
        # Initialize
        init = json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize',
            'params':{'protocolVersion':'2024-11-05','capabilities':{'tools':{}},
            'clientInfo':{'name':'fiber','version':'0.1'}}}) + '\n'
        self.proc.stdin.write(init.encode())
        self.proc.stdin.flush()
        time.sleep(2)
        notif = json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'}) + '\n'
        self.proc.stdin.write(notif.encode())
        self.proc.stdin.flush()
        time.sleep(1)
        self.running = True
        print("MCP client started")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.running = False

    def call_tool(self, name, arguments=None, req_id=10):
        if not self.running or not self.proc:
            return None
        req = json.dumps({'jsonrpc':'2.0','id':req_id,'method':'tools/call',
            'params':{'name': name, 'arguments': arguments or {}}}) + '\n'
        self.proc.stdin.write(req.encode())
        self.proc.stdin.flush()
        # Wait for response
        for _ in range(10):
            time.sleep(0.5)
            if self.proc.stdout and self.proc.stdout.readable():
                line = self.proc.stdout.readline()
                if line:
                    try:
                        d = json.loads(line.decode('utf-8', errors='replace'))
                        if d.get('id') == req_id:
                            return d.get('result') or d.get('error')
                    except:
                        pass
        return None

def main():
    client = MCPClient()
    client.start()

    # Test connections
    print("\n=== Testing MCP ===")
    result = client.call_tool('check_connection', {})
    print(f"check_connection: {result}")

    # Search for chat-related strings
    print("\n=== Searching for ChatScreen ===")
    result = client.call_tool('list_strings_filter', {'filter': 'ChatScreen', 'count': 20, 'offset': 0})
    if result:
        texts = result.get('content', [])
        for item in texts:
            print(f"  {item.get('text', '')[:150]}")

    print("\n=== Searching for Command ===")
    result = client.call_tool('list_strings_filter', {'filter': 'Command', 'count': 20, 'offset': 0})
    if result:
        texts = result.get('content', [])
        for item in texts:
            print(f"  {item.get('text', '')[:150]}")

    print("\n=== Searching for TextPacket ===")
    result = client.call_tool('list_strings_filter', {'filter': 'TextPacket', 'count': 20, 'offset': 0})
    if result:
        texts = result.get('content', [])
        for item in texts:
            print(f"  {item.get('text', '')[:150]}")

    client.stop()
    print("\nDone")

if __name__ == '__main__':
    main()
