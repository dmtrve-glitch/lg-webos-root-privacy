#!/usr/bin/env python3
"""Laptop-side SSAP pairing/info and a one-shot rooted Homebrew exec bridge.

Requires a separately obtained and reviewed SlopBro SSAP module, verified before
import. Does not run SlopBro's exploit or install a root service.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


def private_ip(value):
    addr = ipaddress.ip_address(value)
    if addr.version != 4 or not addr.is_private or addr.is_loopback or addr.is_unspecified or addr.is_link_local:
        raise argparse.ArgumentTypeError('Use the actual private IPv4 address on the TV LAN')
    return str(addr)


def reviewed_module(module_path, manifest_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8-sig'))
    expected = next(x['sha256'] for x in manifest['files'] if x['path'] == 'slopbro.py')
    path = Path(module_path).resolve()
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('SSAP module hash mismatch; review before updating manifest')
    spec = importlib.util.spec_from_file_location('reviewed_tv_ssap', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save_key(path, key):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf8') as output:
        output.write(key)
    os.chmod(str(path), 0o600)
    # POSIX mode does not replace a Windows ACL; use a private user-owned folder.


def make_handler(tv, token, page, result, done, asset_dir=None):
    class Handler(BaseHTTPRequestHandler):
        def authorized(self):
            return self.client_address[0] == tv

        def do_GET(self):
            if not self.authorized():
                self.send_error(403)
                return
            route = self.path.split('?', 1)[0]
            if route == '/maint-' + token + '.html':
                data, content_type = page, 'text/html; charset=utf-8'
            elif asset_dir and route.startswith('/assets-' + token + '/'):
                name = route.split('/', 2)[-1]
                if not name or any(x in name for x in ('/', '\\', '..', '%')):
                    self.send_error(404)
                    return
                path = asset_dir / name
                if path.is_symlink() or not path.is_file() or path.resolve().parent != asset_dir:
                    self.send_error(404)
                    return
                data, content_type = path.read_bytes(), 'application/octet-stream'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if not self.authorized() or self.path != '/result-' + token:
                self.send_error(403)
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 2 * 1024 * 1024:
                    self.send_error(413)
                    return
                value = json.loads(self.rfile.read(size))
                if not isinstance(value, dict):
                    raise ValueError('Expected object')
            except (ValueError, UnicodeDecodeError):
                self.send_error(400)
                return
            result.update(value)
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')
            done.set()

        def log_message(self, *args):
            pass

    return Handler


def exec_once(args, client):
    token = secrets.token_urlsafe(24)
    done, result = threading.Event(), {}
    # Bind only to the explicit LAN interface; port zero chooses a free port.
    handler = make_handler(args.tv, token, b'', result, done, Path(args.asset_dir).resolve() if args.asset_dir else None)
    server = HTTPServer((args.local_ip, args.port), handler)
    server.timeout = 2
    # A stalled HTTP client must not hold the single-use server indefinitely.
    old_get_request = server.get_request
    def get_request():
        connection, address = old_get_request()
        connection.settimeout(5)
        return connection, address
    server.get_request = get_request
    base = 'http://%s:%s' % (args.local_ip, server.server_address[1])
    command = Path(args.command_file).read_text(encoding='utf-8-sig')
    if len(command.encode('utf8')) > 128 * 1024:
        server.server_close()
        raise ValueError('Use an asset file for commands larger than 128 KiB')
    command = command.replace('ASSET_BASE_URL', base + '/assets-' + token)
    timeout = ['/usr/bin/timeout', '-t', str(args.command_timeout)] if args.timeout_style == 'busybox' else ['/usr/bin/timeout', str(args.command_timeout)]
    wrapped = ' '.join(shlex.quote(x) for x in timeout + ['/bin/sh', '-c', command])
    page = '''<!doctype html><meta charset="utf-8"><title>LG maintenance</title>
<body style="background:#152130;color:white;font:30px sans-serif;padding:50px">
<h2>LG maintenance</h2><p id="s">Maintenance in progress. This window will close.</p>
<script>(function(){var bridge;
function report(value){var x=new XMLHttpRequest();x.open('POST',RESULT_URL,true);x.setRequestHeader('Content-Type','application/json');x.onload=function(){document.getElementById('s').textContent='Complete. Closing.';setTimeout(function(){window.close();},500);};x.send(JSON.stringify(value));}
try{bridge=(typeof webOSServiceBridge==='function')?new webOSServiceBridge():new PalmServiceBridge();bridge.onservicecallback=function(raw){try{report(JSON.parse(raw));}catch(e){report({error:String(e)});}};bridge.call('luna://org.webosbrew.hbchannel.service/exec',JSON.stringify({command:COMMAND}));}catch(e){report({error:String(e)});}})();</script>'''
    page = page.replace('RESULT_URL', json.dumps('/result-' + token)).replace('COMMAND', json.dumps(wrapped)).encode('utf8')
    # Rebuild the handler before accepting any requests.
    server.RequestHandlerClass = make_handler(args.tv, token, page, result, done, Path(args.asset_dir).resolve() if args.asset_dir else None)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        reply = client.request('ssap://system.launcher/launch', {'id': args.app_id, 'params': {'interactiveUrl': base + '/maint-' + token + '.html'}})
        if not reply.get('payload', {}).get('returnValue'):
            raise RuntimeError('Maintenance app launch rejected')
        print('Temporary maintenance page opened; command timeout %ss.' % args.command_timeout, flush=True)
        if not done.wait(args.command_timeout + 10):
            raise TimeoutError('No result: inspect TV state before retrying; command may have run. Hold Back 2-3 seconds if maintenance page remains.')
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf8')
        for field in ('stdoutString', 'stderrString'):
            if result.get(field):
                print(str(result[field])[:16000])
        print('Root response:', result.get('returnValue'), 'Full response saved:', args.output)
        # Shell exit codes are service-version dependent: inspect the full response too.
        return 0 if result.get('returnValue') is True and not result.get('error') else 2
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=6)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tv', required=True, type=private_ip)
    p.add_argument('--module', required=True)
    p.add_argument('--manifest', required=True)
    p.add_argument('--key-file', required=True)
    p.add_argument('--action', choices=['pair', 'info', 'exec'], required=True)
    p.add_argument('--local-ip', type=private_ip)
    p.add_argument('--app-id')
    p.add_argument('--port', type=int, default=0)
    p.add_argument('--command-file')
    p.add_argument('--asset-dir')
    p.add_argument('--output')
    p.add_argument('--command-timeout', type=int, default=20)
    p.add_argument('--timeout-style', choices=['busybox', 'gnu'], default='busybox')
    args = p.parse_args()
    if args.action == 'exec' and (not all([args.local_ip, args.app_id, args.command_file, args.output]) or not 5 <= args.command_timeout <= 45):
        p.error('exec requires local-ip/app-id/command-file/output and a 5..45 second timeout')
    key_file = Path(args.key_file).resolve()
    if not key_file.is_file() and args.action != 'pair':
        p.error('Pair explicitly first; no credential found')
    module = reviewed_module(args.module, args.manifest)
    client = module.SSAPClient(module.WebSocket.connect(args.tv, 3001, secure=True))
    try:
        stored = key_file.read_text(encoding='utf8').strip() if key_file.exists() else None
        key = client.register(stored, module.DEFAULT_MANIFEST)
        if key and key != stored:
            save_key(key_file, key)
        if args.action == 'pair':
            print('Paired; credential stored privately. Its contents are not logged.')
            return 0
        if args.action == 'info':
            result = {endpoint: client.request('ssap://' + endpoint) for endpoint in ['system/getSystemInfo', 'com.webos.service.update/getCurrentSWInformation']}
            if args.output:
                Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf8')
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        return exec_once(args, client)
    finally:
        client.close()


if __name__ == '__main__':
    raise SystemExit(main())
