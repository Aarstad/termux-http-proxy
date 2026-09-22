"""Loopback regression tests. PROXY_SOURCE selects another repository's copy.

Run: python3 tests/test_proxy.py
Requires cc with AddressSanitizer support. Builds only in a temporary directory.
"""
import os
import concurrent.futures
import time
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = str(Path(cls.temp.name) / 'proxy')
        source = os.environ.get('PROXY_SOURCE', str(Path(__file__).resolve().parents[1] / 'termux-http-proxy.c'))
        cls.source = str(Path(source).resolve())
        subprocess.run(['cc', '-Wall', '-Wextra', '-Wpedantic', '-O1', '-g',
                        '-fsanitize=address', '-o', cls.binary, source], check=True)

    def setUp(self):
        self.proxy = subprocess.Popen([self.binary], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop_proxy)
        self.port = int(self.proxy.stdout.readline())
        self.server = socket.socket()
        self.addCleanup(self.server.close)
        self.server.settimeout(3)
        self.server.bind(('127.0.0.1', 0))
        self.server.listen()
        self.target = f'127.0.0.1:{self.server.getsockname()[1]}'
        self.client = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        self.addCleanup(self.client.close)

    def stop_proxy(self):
        self.proxy.terminate()
        _, errors = self.proxy.communicate(timeout=5)
        self.assertNotIn(b'ERROR: AddressSanitizer', errors, errors.decode())
        self.assertIn(self.proxy.returncode, (-15, 0), errors.decode())

    def upstream(self):
        conn, _ = self.server.accept()
        conn.settimeout(3)
        self.addCleanup(conn.close)
        return conn

    def receive(self, conn, length):
        data = b''
        while len(data) < length:
            part = conn.recv(length - len(data))
            if not part:
                break
            data += part
        return data

    def test_http_body_and_headers(self):
        payload = b'hello\x00world'
        self.client.sendall((f'POST http://{self.target}/test HTTP/1.1\r\n'
                             f'Host: localhost\r\nContent-Length: {len(payload)}\r\n\r\n').encode() + payload)
        conn = self.upstream()
        expected = (f'POST /test HTTP/1.1\r\nHost: localhost\r\n'
                    f'Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n').encode() + payload
        self.assertEqual(self.receive(conn, len(expected)), expected)

    def test_dropped_final_header(self):
        self.client.sendall((f'GET http://{self.target}/ HTTP/1.1\r\n'
                             'Host: localhost\r\nProxy-Connection: keep-alive\r\n\r\n').encode())
        conn = self.upstream()
        expected = b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
        self.assertEqual(self.receive(conn, len(expected)), expected)

    def test_connect_early_payload_and_response(self):
        payload = b'early\x00payload'
        self.client.sendall(f'CONNECT {self.target} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode() + payload)
        conn = self.upstream()
        self.assertEqual(self.receive(conn, len(payload)), payload)
        reply = b'HTTP/1.1 200 Connection Established\r\n\r\n'
        self.assertEqual(self.receive(self.client, len(reply)), reply)
        conn.sendall(b'response')
        self.assertEqual(self.receive(self.client, 8), b'response')
        self.client.sendall(b'later')
        self.assertEqual(self.receive(conn, 5), b'later')

    def test_chunked_rejected_before_dial(self):
        for header in ('Transfer-Encoding: chunked', 'tRaNsFeR-EnCoDiNg: chunked'):
            with self.subTest(header=header):
                with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
                    client.sendall((f'POST http://{self.target}/ HTTP/1.1\r\n'
                                    f'Host: localhost\r\n{header}\r\n\r\n'
                                    '5\r\nhello\r\n0\r\n\r\n').encode())
                    self.assertTrue(client.recv(4096).startswith(b'HTTP/1.1 501 '))
        self.server.settimeout(0.1)
        with self.assertRaises(TimeoutError):
            self.server.accept()

    def test_refused_connection(self):
        self.server.close()
        self.client.sendall(f'CONNECT {self.target} HTTP/1.1\r\n\r\n'.encode())
        self.assertTrue(self.client.recv(4096).startswith(b'HTTP/1.1 502 '))

    def test_bidirectional_backpressure_and_half_close(self):
        self.client.sendall(f'CONNECT {self.target} HTTP/1.1\r\n\r\n'.encode())
        conn = self.upstream()
        reply = b'HTTP/1.1 200 Connection Established\r\n\r\n'
        self.assertEqual(self.receive(self.client, len(reply)), reply)
        payload = bytes(range(256)) * 16384
        for sock in (self.client, conn):
            sock.settimeout(10)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        def send(sock, data):
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            forward = pool.submit(send, self.client, payload)
            reverse = pool.submit(send, conn, payload[::-1])
            # Both directions fill before either receiver starts draining.
            time.sleep(0.15)
            upstream = pool.submit(self.receive, conn, len(payload))
            downstream = pool.submit(self.receive, self.client, len(payload))
            self.assertEqual(upstream.result(timeout=15), payload)
            self.assertEqual(downstream.result(timeout=15), payload[::-1])
            forward.result(timeout=15)
            reverse.result(timeout=15)
        self.assertEqual(conn.recv(1), b'')
        self.assertEqual(self.client.recv(1), b'')

    def test_setup_deadlines_and_backpressure(self):
        binary = str(Path(self.temp.name) / 'deadlines')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Wpedantic', '-O1', '-g',
                        '-fsanitize=address', f'-DPROXY_SOURCE="{self.source}"',
                        '-o', binary, str(Path(__file__).with_name('test_deadlines.c'))], check=True)
        subprocess.run([binary], check=True, timeout=5)


if __name__ == '__main__':
    unittest.main()
