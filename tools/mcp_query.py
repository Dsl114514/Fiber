import subprocess, json, time, sys

MCP_SERVER = r'C:\Python314\Lib\site-packages'
IDA_RPC = 'http://127.0.0.1:13337'

def call_tool(name, arguments=None):
    proc = subprocess.Popen(
        [sys.executable, '-m', 'ida_pro_mcp.server', '--ida-rpc', IDA_RPC],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=MCP_SERVER
    )
    try:
        init = json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize',
            'params':{'protocolVersion':'2024-11-05','capabilities':{'tools':{}},
            'clientInfo':{'name':'fiber','version':'0.1'}}}) + '\n'
        proc.stdin.write(init.encode())
        proc.stdin.flush()
        time.sleep(1)
        notif = json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'}) + '\n'
        proc.stdin.write(notif.encode())
        proc.stdin.flush()
        time.sleep(0.5)
        req = json.dumps({'jsonrpc':'2.0','id':2,'method':'tools/call',
            'params':{'name': name, 'arguments': arguments or {}}}) + '\n'
        proc.stdin.write(req.encode())
        proc.stdin.flush()
        time.sleep(3)
        proc.stdin.close()
        stdout = proc.stdout.read().decode('utf-8', errors='replace')
        for line in stdout.strip().split('\n'):
            if line:
                try:
                    d = json.loads(line)
                    if d.get('id') == 2 and 'result' in d:
                        return d['result']
                except:
                    pass
        return None
    finally:
        proc.terminate()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('command', help='Command: strings, func, xrefs, decompile')
    parser.add_argument('args', nargs='*', help='Arguments')
    args = parser.parse_args()

    if args.command == 'strings':
        result = call_tool('list_strings_filter', {
            'filter': args.args[0] if args.args else 'chat',
            'count': 50,
            'offset': 0
        })
        print(json.dumps(result, indent=2, default=str) if result else 'No result')
    elif args.command == 'func':
        result = call_tool('get_function_by_name', {'name': args.args[0] if args.args else ''})
        print(json.dumps(result, indent=2, default=str) if result else 'No result')
    elif args.command == 'xrefs':
        result = call_tool('get_xrefs_to', {'address': args.args[0] if args.args else '0'})
        print(json.dumps(result, indent=2, default=str) if result else 'No result')
    elif args.command == 'decompile':
        result = call_tool('decompile_function', {'address': args.args[0] if args.args else '0'})
        print(json.dumps(result, indent=2, default=str) if result else 'No result')
    else:
        print(f'Unknown command: {args.command}')
