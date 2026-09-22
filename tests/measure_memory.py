"""Measure release-build process memory on Linux/Android; no installation needed.

python3 tests/measure_memory.py --bun-js ../claude-code-termux-musl/libexec/dns-proxy.js
RSS/PSS exclude socket/pipe kernel memory. Results are workload/device specific.
"""
import argparse
import contextlib
import json
from pathlib import Path
import select
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time


def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('Unexpected EOF')
        data.extend(part)
    return bytes(data)


def snapshot(pid):
    proc = Path('/proc') / str(pid)
    values = {}
    for line in (proc / 'status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ('VmRSS', 'Threads'):
            values[key] = int(value.split()[0])
    try:
        for line in (proc / 'smaps_rollup').read_text().splitlines():
            key, _, value = line.partition(':')
            if key in ('Pss', 'Private_Clean', 'Private_Dirty'):
                values[key] = int(value.split()[0])
    except (PermissionError, FileNotFoundError):
        pass
    return values


def sample(pid):
    samples = []
    for _ in range(5):
        samples.append(snapshot(pid))
        time.sleep(0.1)
    return {key: statistics.median(row[key] for row in samples) for key in samples[0]}


def measure(command, tunnels):
    with contextlib.ExitStack() as stack:
        proxy = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        def stop():
            proxy.terminate()
            try:
                _, errors = proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                _, errors = proxy.communicate()
            if errors:
                print(errors.decode(), file=sys.stderr)
        stack.callback(stop)
        if not select.select([proxy.stdout], [], [], 10)[0]:
            raise RuntimeError('Proxy did not announce a port')
        port = int(proxy.stdout.readline())
        time.sleep(0.5)
        idle = sample(proxy.pid)
        listener = stack.enter_context(socket.socket())
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(5)
        target = listener.getsockname()[1]
        payload = bytes(range(256)) * 256
        for _ in range(tunnels):
            client = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=5))
            client.sendall(f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
            upstream, _ = listener.accept()
            stack.enter_context(upstream)
            upstream.settimeout(5)
            header = bytearray()
            while not header.endswith(b'\r\n\r\n'):
                header.extend(receive(client, 1))
            if not header.startswith(b'HTTP/1.1 200 '):
                raise RuntimeError(f'CONNECT failed: {header!r}')
            client.sendall(payload)
            if receive(upstream, len(payload)) != payload:
                raise RuntimeError('Upstream data mismatch')
            upstream.sendall(payload)
            if receive(client, len(payload)) != payload:
                raise RuntimeError('Downstream data mismatch')
        active = sample(proxy.pid)
        return {'idle': idle, 'open_tunnels_after_transfer': active, 'tunnels': tunnels,
                'bytes_per_direction_per_tunnel': len(payload)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'termux-http-proxy.c')
    parser.add_argument('--bun-js', type=Path)
    parser.add_argument('--tunnels', type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.tunnels <= 32:
        parser.error('--tunnels must be between 1 and 32')
    with tempfile.TemporaryDirectory(prefix='proxy-memory-') as tmp:
        binary = str(Path(tmp) / 'dns-proxy')
        subprocess.run(['cc', '-O2', '-o', binary, str(args.source)], check=True)
        result = {'units': 'KiB except Threads/counts', 'C': measure([binary], args.tunnels)}
        if args.bun_js:
            bun = shutil.which('bun')
            if not bun:
                parser.error('bun is not installed')
            result['Bun'] = measure([bun, str(args.bun_js.resolve())], args.tunnels)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
