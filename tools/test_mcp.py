import subprocess, json, time, sys

proc = subprocess.Popen(
    [sys.executable, '-m', 'ida_pro_mcp.server', '--ida-rpc', 'http://127.0.0.1:13337'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    cwd=r'C:\Python314\Lib\site-packages'
)

# Initialize
init = json.dumps({
    'jsonrpc': '2.0',
    'id': 1,
    'method': 'initialize',
    'params': {
        'protocolVersion': '2024-11-05',
        'capabilities': {'tools': {}},
        'clientInfo': {'name': 'fiber', 'version': '0.1'}
    }
}) + '\n'
proc.stdin.write(init.encode())
proc.stdin.flush()
time.sleep(3)

# Notification
notif = json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n'
proc.stdin.write(notif.encode())
proc.stdin.flush()
time.sleep(1)

# Tools list
tools_req = json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}}) + '\n'
proc.stdin.write(tools_req.encode())
proc.stdin.flush()
time.sleep(2)

# Check connection
check = json.dumps({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'check_connection', 'arguments': {}}}) + '\n'
proc.stdin.write(check.encode())
proc.stdin.flush()
time.sleep(2)

proc.stdin.close()
stdout = proc.stdout.read().decode('utf-8', errors='replace')
stderr = proc.stderr.read().decode('utf-8', errors='replace')
print('STDERR:', stderr[:200])
for line in stdout.strip().split('\n'):
    if line:
        try:
            d = json.loads(line)
            rid = d.get('id', '?')
            if 'result' in d:
                if rid == 2:
                    tools = d['result'].get('tools', [])
                    print(f'Tools ({len(tools)}):')
                    for t in tools:
                        print(f'  - {t["name"]}: {t.get("description","")[:80]}')
                elif rid == 3:
                    print(f'check_connection: {d["result"]}')
                else:
                    print(f'id={rid}: {str(d["result"])[:200]}')
            elif 'error' in d:
                print(f'id={rid} ERR: {d["error"]}')
        except Exception as e:
            print(f'Parse err: {line[:200]} {e}')
