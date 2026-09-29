"""Loopback regression tests. PROXY_SOURCE selects another repository's copy.

Run: python3 tests/test_proxy.py
Requires cc with AddressSanitizer support. Builds only in a temporary directory.
PROXY_NETWORK_TESTS=1 also runs tests that resolve real names over the network.
"""
import base64
import os
import signal
import concurrent.futures
import time
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest

SOURCE = str(Path(os.environ.get(
    'PROXY_SOURCE', Path(__file__).resolve().parents[1] / 'termux-http-proxy.c')).resolve())


def build(directory, name, *defines):
    binary = str(Path(directory) / name)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Wpedantic', '-O1', '-g',
                    '-fsanitize=address', *defines, '-o', binary, SOURCE], check=True)
    return binary


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_listening(port, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f'nothing listening on {port}')


def has_ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(('::1', 0))
        return True
    except OSError:
        return False


def socks_request(host, port, command=1):
    """A SOCKS5 request for an IPv4/IPv6 literal or a domain name."""
    for family, atyp in ((socket.AF_INET, 1), (socket.AF_INET6, 4)):
        try:
            return bytes([5, command, 0, atyp]) + socket.inet_pton(family, host) + port.to_bytes(2, 'big')
        except OSError:
            pass
    return bytes([5, command, 0, 3, len(host)]) + host.encode() + port.to_bytes(2, 'big')


def socks_auth(user, password):
    return bytes([1, len(user)]) + user.encode() + bytes([len(password)]) + password.encode()


def recv_exact(conn, length):
    data = b''
    while len(data) < length:
        part = conn.recv(length - len(data))
        if not part:
            break
        data += part
    return data


def socks_reply(conn):
    """Reads a SOCKS5 reply; returns (code, bound address bytes)."""
    head = recv_exact(conn, 4)
    if len(head) < 4:
        return None, b''
    size = {1: 4, 4: 16}.get(head[3], 0)
    return head[1], recv_exact(conn, size + 2)


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.source = SOURCE
        cls.binary = build(cls.temp.name, 'proxy')

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

    def test_localhost_by_name(self):
        self.client.sendall(f'CONNECT localhost:{self.server.getsockname()[1]} HTTP/1.1\r\n\r\n'.encode())
        conn = self.upstream()
        reply = b'HTTP/1.1 200 Connection Established\r\n\r\n'
        self.assertEqual(self.receive(self.client, len(reply)), reply)
        conn.sendall(b'hi')
        self.assertEqual(self.receive(self.client, 2), b'hi')

    @unittest.skipUnless(has_ipv6_loopback(), 'no IPv6 loopback')
    def test_bracketed_ipv6_target(self):
        with socket.socket(socket.AF_INET6) as server:
            server.settimeout(3)
            server.bind(('::1', 0))
            server.listen()
            self.client.sendall(f'CONNECT [::1]:{server.getsockname()[1]} HTTP/1.1\r\n\r\n'.encode())
            conn, _ = server.accept()
            self.addCleanup(conn.close)
            reply = b'HTTP/1.1 200 Connection Established\r\n\r\n'
            self.assertEqual(self.receive(self.client, len(reply)), reply)

    def test_malformed_targets_rejected_before_dial(self):
        for target in ('host:notaport', 'host:0', 'host:70000', '[::1', ''):
            with self.subTest(target=target):
                with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
                    client.sendall(f'CONNECT {target} HTTP/1.1\r\n\r\n'.encode())
                    self.assertTrue(client.recv(4096).startswith(b'HTTP/1.1 400 '))

    def test_socks_ipv4_with_early_payload(self):
        # Greeting, request and first payload bytes in one write, as optimistic clients send.
        host, port = self.target.split(':')
        self.client.sendall(b'\x05\x01\x00' + socks_request(host, int(port)) + b'early')
        conn = self.upstream()
        self.assertEqual(self.receive(conn, 5), b'early')
        self.assertEqual(self.receive(self.client, 2), b'\x05\x00')
        code, bound = socks_reply(self.client)
        self.assertEqual(code, 0)
        self.assertEqual(bound[:4], socket.inet_aton('127.0.0.1'))
        conn.sendall(b'pong')
        self.assertEqual(self.receive(self.client, 4), b'pong')

    def test_socks_one_byte_at_a_time(self):
        port = int(self.target.split(':')[1])
        for message, reply_len in ((b'\x05\x02\x00\x02', 2), (socks_request('localhost', port), None)):
            for byte in message:
                self.client.send(bytes([byte]))
                time.sleep(0.005)
            if reply_len:
                self.assertEqual(self.receive(self.client, reply_len), b'\x05\x00')
        conn = self.upstream()
        self.assertEqual(socks_reply(self.client)[0], 0)
        self.client.sendall(b'ping')
        self.assertEqual(self.receive(conn, 4), b'ping')

    def test_socks_bracketless_ipv6_literal(self):
        if not has_ipv6_loopback():
            self.skipTest('::1 unavailable')
        with socket.socket(socket.AF_INET6) as server6:
            server6.bind(('::1', 0))
            server6.listen()
            server6.settimeout(3)
            self.client.sendall(b'\x05\x01\x00' + socks_request('::1', server6.getsockname()[1]))
            conn, _ = server6.accept()
            conn.close()
            self.assertEqual(self.receive(self.client, 2), b'\x05\x00')
            code, bound = socks_reply(self.client)
            self.assertEqual(code, 0)
            self.assertEqual(len(bound), 18)

    def test_socks_refused_is_code_5(self):
        host, port = self.target.split(':')
        self.server.close()
        self.client.sendall(b'\x05\x01\x00' + socks_request(host, int(port)))
        self.assertEqual(self.receive(self.client, 2), b'\x05\x00')
        self.assertEqual(socks_reply(self.client)[0], 5)

    def test_socks_unsupported_requests_rejected_before_dial(self):
        host, port = self.target.split(':')
        cases = {
            'bind': (socks_request(host, int(port), command=2), 7),
            'udp associate': (socks_request(host, int(port), command=3), 7),
            'address type': (b'\x05\x01\x00\x09' + b'\x00' * 6, 8),
            'empty name': (b'\x05\x01\x00\x03\x00\x01\xbb', 1),
            'nul in name': (b'\x05\x01\x00\x03\x03a\x00b\x01\xbb', 1),
            'port 0': (socks_request(host, 0), 1),
        }
        for name, (request, code) in cases.items():
            with self.subTest(name=name):
                with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
                    client.sendall(b'\x05\x01\x00' + request)
                    self.assertEqual(self.receive(client, 2), b'\x05\x00')
                    self.assertEqual(socks_reply(client)[0], code)
                    self.assertEqual(client.recv(1), b'')
        self.server.settimeout(0.1)
        with self.assertRaises(TimeoutError):
            self.server.accept()

    def test_socks_methods_without_a_token(self):
        # Credentials a client insists on are accepted and ignored; a client that
        # offers no method we support is turned away.
        host, port = self.target.split(':')
        self.client.sendall(b'\x05\x01\x02' + socks_auth('me', 'anything') + socks_request(host, int(port)))
        self.assertEqual(self.receive(self.client, 4), b'\x05\x02\x01\x00')
        self.upstream()
        self.assertEqual(socks_reply(self.client)[0], 0)
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'\x05\x01\x01')  # GSSAPI only
            self.assertEqual(self.receive(client, 3), b'\x05\xff')

    def test_unit_tests(self):
        self.run_c_test('test_units.c')

    def test_event_loop(self):
        self.run_c_test('test_event_loop.c')

    def run_c_test(self, name):
        binary = str(Path(self.temp.name) / Path(name).stem)
        subprocess.run(['cc', '-Wall', '-Wextra', '-Wpedantic', '-O1', '-g',
                        '-fsanitize=address', f'-DPROXY_SOURCE="{self.source}"',
                        '-o', binary, str(Path(__file__).with_name(name))], check=True)
        subprocess.run([binary], check=True, timeout=60)


class FootprintTests(unittest.TestCase):
    """The release build stays small once its resolver is loaded.

    Loading the async resolver through libandroid.so instead of libnetd_client.so
    once took this from 3MB to 45MB RSS (1,187 mapped objects) with every other test
    still passing. The limits are loose; they exist to catch that kind of jump.
    """

    def test_release_build_rss(self):
        with tempfile.TemporaryDirectory(prefix='proxy-rss-') as tmp:
            binary = str(Path(tmp) / 'proxy')
            subprocess.run(['cc', '-O2', '-o', binary, SOURCE], check=True)
            # The with block closes the pipes and waits, so no stream is left unclosed.
            with subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proxy:
                try:
                    int(proxy.stdout.readline())  # Past resolver_init() once the port is printed
                    status = Path(f'/proc/{proxy.pid}/status').read_text()
                    rss = int(next(l for l in status.splitlines() if l.startswith('VmRSS:')).split()[1])
                    maps = Path(f'/proc/{proxy.pid}/maps').read_text()
                    objects = {l.split()[-1] for l in maps.splitlines() if '.so' in l}
                finally:
                    proxy.terminate()
            self.assertLess(rss, 8 * 1024, f'VmRSS {rss} kB')
            self.assertLess(len(objects), 40, sorted(objects))


class ArgumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-args-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build(cls.temp.name, 'proxy')

    def test_unknown_arguments_exit_2(self):
        for args in (['--bogus'], ['--port', 'abc'], ['--port', '0'], ['70000']):
            with self.subTest(args=args):
                result = subprocess.run([self.binary, *args], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b'usage:', result.stderr)

    def test_bad_token_file_refused_before_listening(self):
        token = Path(self.temp.name) / 'open-token'
        token.write_text('0123456789abcdef0123\n')
        token.chmod(0o644)
        result = subprocess.run([self.binary, '--auth-file', str(token)], capture_output=True,
                                timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'chmod 600', result.stderr)
        self.assertEqual(result.stdout, b'')


class AuthTests(unittest.TestCase):
    """--auth-file: nothing is resolved or dialed without the token."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-auth-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build(cls.temp.name, 'proxy')
        cls.token_path = Path(cls.temp.name) / 'token'

    def setUp(self):
        self.proxy = subprocess.Popen([self.binary, '--auth-file', str(self.token_path)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.addCleanup(self.stop_proxy)
        self.port = int(self.proxy.stdout.readline())
        self.token = self.token_path.read_text().strip()
        self.server = socket.socket()
        self.addCleanup(self.server.close)
        self.server.settimeout(3)
        self.server.bind(('127.0.0.1', 0))
        self.server.listen()
        self.target = f'127.0.0.1:{self.server.getsockname()[1]}'

    def stop_proxy(self):
        self.proxy.terminate()
        _, errors = self.proxy.communicate(timeout=5)
        self.assertNotIn(b'ERROR: AddressSanitizer', errors, errors.decode())

    def ask(self, request):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(request)
            return client.recv(4096)

    def auth(self, userpass):
        return 'Proxy-Authorization: Basic ' + base64.b64encode(userpass.encode()).decode()

    def assert_not_dialed(self):
        self.server.settimeout(0.1)
        with self.assertRaises(TimeoutError):
            self.server.accept()

    def test_token_file_created_private(self):
        mode = stat.S_IMODE(self.token_path.stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertRegex(self.token, r'^[0-9a-f]{32}$')

    def test_missing_credentials_get_407(self):
        reply = self.ask(f'CONNECT {self.target} HTTP/1.1\r\n\r\n'.encode())
        self.assertTrue(reply.startswith(b'HTTP/1.1 407 '), reply)
        self.assertIn(b'Proxy-Authenticate: Basic realm="termux-http-proxy"', reply)
        self.assert_not_dialed()

    def test_wrong_credentials_get_407(self):
        for header in (self.auth('proxy:' + self.token[:-1]),
                       self.auth('proxy:' + self.token + 'x'),
                       self.auth(self.token + ':'),
                       'Proxy-Authorization: Bearer ' + self.token):
            with self.subTest(header=header):
                reply = self.ask(f'CONNECT {self.target} HTTP/1.1\r\n{header}\r\n\r\n'.encode())
                self.assertTrue(reply.startswith(b'HTTP/1.1 407 '), reply)
        self.assert_not_dialed()

    def test_unauthenticated_names_are_not_resolved(self):
        # A name that would need a lookup still gets 407, not a DNS error: the proxy
        # cannot be used as a resolver oracle either.
        reply = self.ask(b'CONNECT no-such-host.invalid:443 HTTP/1.1\r\n\r\n')
        self.assertTrue(reply.startswith(b'HTTP/1.1 407 '), reply)

    def test_connect_with_token(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(f'CONNECT {self.target} HTTP/1.1\r\n{self.auth("anyone:" + self.token)}\r\n\r\n'.encode())
            conn, _ = self.server.accept()
            with conn:
                self.assertTrue(client.recv(4096).startswith(b'HTTP/1.1 200 '))
                conn.sendall(b'ok')
                self.assertEqual(client.recv(2), b'ok')

    def test_http_with_token_strips_credentials(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall((f'GET http://{self.target}/ HTTP/1.1\r\nHost: localhost\r\n'
                            f'{self.auth("p:" + self.token)}\r\n\r\n').encode())
            conn, _ = self.server.accept()
            with conn:
                conn.settimeout(3)
                expected = b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
                data = b''
                while len(data) < len(expected):
                    part = conn.recv(4096)
                    if not part:
                        break
                    data += part
                self.assertEqual(data, expected)

    @unittest.skipUnless(subprocess.run(['sh', '-c', 'command -v curl'], capture_output=True).returncode == 0,
                         'curl not installed')
    def test_curl_with_proxy_url_credentials(self):
        # What real clients do with HTTPS_PROXY=http://user:token@127.0.0.1:port.
        with socket.socket() as origin:
            origin.bind(('127.0.0.1', 0))
            origin.listen()
            origin.settimeout(5)
            port = origin.getsockname()[1]
            curl = subprocess.Popen(['curl', '-s', '-m', '5', '-p', '-x',
                                     f'http://proxy:{self.token}@127.0.0.1:{self.port}',
                                     f'http://127.0.0.1:{port}/'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            conn, _ = origin.accept()
            with conn:
                conn.settimeout(5)
                request = conn.recv(4096)
                self.assertTrue(request.startswith(b'GET / HTTP/1.1'), request)
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello')
            out, _ = curl.communicate(timeout=10)
            self.assertEqual(out, b'hello')


    def test_socks_requires_the_password_method(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'\x05\x01\x00' + socks_request('127.0.0.1', 1))
            self.assertEqual(recv_exact(client, 3), b'\x05\xff')
        self.assert_not_dialed()

    def test_socks_wrong_password(self):
        host, port = self.target.split(':')
        for password in (self.token[:-1], self.token + 'x', ''):
            with self.subTest(password=password):
                with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
                    client.sendall(b'\x05\x01\x02' + socks_auth('proxy', password)
                                   + socks_request(host, int(port)))
                    self.assertEqual(recv_exact(client, 5), b'\x05\x02\x01\x01')
        # Nor is a name looked up for a client with the wrong password.
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'\x05\x01\x02' + socks_auth('p', 'wrong-token-here')
                           + socks_request('no-such-host.invalid', 443))
            self.assertEqual(recv_exact(client, 5), b'\x05\x02\x01\x01')
        self.assert_not_dialed()

    def test_socks_with_token(self):
        host, port = self.target.split(':')
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'\x05\x02\x00\x02' + socks_auth('anyone', self.token)
                           + socks_request(host, int(port)))
            conn, _ = self.server.accept()
            with conn:
                self.assertEqual(recv_exact(client, 4), b'\x05\x02\x01\x00')
                self.assertEqual(socks_reply(client)[0], 0)
                conn.sendall(b'ok')
                self.assertEqual(client.recv(2), b'ok')

    @unittest.skipUnless(subprocess.run(['sh', '-c', 'command -v curl'], capture_output=True).returncode == 0,
                         'curl not installed')
    def test_curl_socks5h_with_credentials(self):
        with socket.socket() as origin:
            origin.bind(('127.0.0.1', 0))
            origin.listen()
            origin.settimeout(5)
            port = origin.getsockname()[1]
            curl = subprocess.Popen(['curl', '-s', '-m', '5', '-x',
                                     f'socks5h://proxy:{self.token}@127.0.0.1:{self.port}',
                                     f'http://localhost:{port}/'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            conn, _ = origin.accept()
            with conn:
                conn.settimeout(5)
                self.assertTrue(conn.recv(4096).startswith(b'GET / HTTP/1.1'))
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello')
            out, _ = curl.communicate(timeout=10)
            self.assertEqual(out, b'hello')


class LogTests(unittest.TestCase):
    """--log: a line per connection, written when it ends."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-log-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build(cls.temp.name, 'proxy')
        cls.token_path = Path(cls.temp.name) / 'token'

    def setUp(self):
        self.log = Path(self.temp.name) / f'{self._testMethodName}.log'
        self.proxy = subprocess.Popen([self.binary, '--auth-file', str(self.token_path),
                                       '--log', str(self.log)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.addCleanup(self.stop_proxy)
        self.port = int(self.proxy.stdout.readline())
        self.token = self.token_path.read_text().strip()
        self.server = socket.socket()
        self.addCleanup(self.server.close)
        self.server.settimeout(3)
        self.server.bind(('127.0.0.1', 0))
        self.server.listen()
        self.target_port = self.server.getsockname()[1]

    def stop_proxy(self):
        self.proxy.terminate()
        _, errors = self.proxy.communicate(timeout=5)
        self.assertNotIn(b'ERROR: AddressSanitizer', errors, errors.decode())

    def lines(self, count):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            lines = self.log.read_text().splitlines() if self.log.exists() else []
            if len(lines) >= count:
                return lines
            time.sleep(0.02)
        self.fail(f'expected {count} log lines, got: {lines}')

    def fields(self, line):
        # "YYYY-MM-DD HH:MM:SS proto target key=value..."
        date, clock, proto, target, *rest = line.split(' ')
        self.assertRegex(f'{date} {clock}', r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$')
        return dict(proto=proto, target=target, **dict(kv.split('=', 1) for kv in rest))

    def test_tunnel_line_counts_bytes_both_ways(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'\x05\x01\x02' + socks_auth('claude', self.token)
                           + socks_request('localhost', self.target_port) + b'x' * 1000)
            conn, _ = self.server.accept()
            recv_exact(client, 4)
            socks_reply(client)
            conn.sendall(b'y' * 3000)
            recv_exact(client, 3000)
            self.assertEqual(len(recv_exact(conn, 1000)), 1000)
            conn.close()
        line = self.fields(self.lines(1)[0])
        self.assertEqual(line['proto'], 'socks5')
        self.assertEqual(line['target'], f'localhost:{self.target_port}')
        self.assertEqual(line['user'], 'claude')
        self.assertIn(line['addr'], ('127.0.0.1', '::1'))
        self.assertEqual(line['result'], 'ok')
        self.assertEqual((line['up'], line['down']), ('1000', '3000'))
        self.assertRegex(line['time'], r'^\d+\.\d{3}s$')
        self.assertEqual(stat.S_IMODE(self.log.stat().st_mode), 0o600)

    def test_refusals_are_logged_without_secrets(self):
        auth = base64.b64encode(f'agy:{self.token}'.encode()).decode()
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'CONNECT evil.test:443 HTTP/1.1\r\n\r\n')
            client.recv(4096)
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'\x05\x01\x02' + socks_auth('bad user', 'wrong-token-here'))
            recv_exact(client, 4)
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall((f'GET http://127.0.0.1:{self.target_port}/private?key=hunter2 HTTP/1.1\r\n'
                            f'Proxy-Authorization: Basic {auth}\r\n\r\n').encode())
            conn, _ = self.server.accept()
            conn.close()
            client.recv(4096)
        lines = self.lines(3)
        refused, bad_password, http = (self.fields(line) for line in lines)
        self.assertEqual((refused['proto'], refused['target'], refused['result']),
                         ('connect', 'evil.test:443', 'auth-failed'))
        self.assertEqual((bad_password['proto'], bad_password['user'], bad_password['result']),
                         ('socks5', 'bad?user', 'auth-failed'))
        self.assertEqual((http['proto'], http['target'], http['user']),
                         ('http', f'127.0.0.1:{self.target_port}', 'agy'))
        text = self.log.read_text()
        self.assertNotIn('hunter2', text)
        self.assertNotIn('private', text)
        self.assertNotIn(self.token, text)

    def test_stderr_log_has_no_timestamps(self):
        proxy = subprocess.Popen([self.binary, '--log', '-'], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        port = int(proxy.stdout.readline())
        with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
            client.sendall(b'CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n')
            client.recv(4096)
        time.sleep(0.2)
        proxy.terminate()
        _, errors = proxy.communicate(timeout=5)
        self.assertTrue(errors.startswith(b'connect 127.0.0.1:1 user=- addr=- result=refused '), errors)

    def test_stderr_log_needs_foreground(self):
        result = subprocess.run([self.binary, '--port', str(free_port()), '--log', '-'],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'needs -f', result.stderr)


class DenyTests(unittest.TestCase):
    """--deny-file: listed domains are refused before anything is resolved or dialed."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-deny-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build(cls.temp.name, 'proxy')

    def setUp(self):
        self.deny = Path(self.temp.name) / 'deny'
        self.deny.write_text('# test list\nlocalhost\nblocked.invalid\n')
        self.log = Path(self.temp.name) / f'{self._testMethodName}.log'
        self.proxy = subprocess.Popen([self.binary, '--deny-file', str(self.deny), '--log', str(self.log)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.addCleanup(self.stop_proxy)
        self.port = int(self.proxy.stdout.readline())
        self.server = socket.socket()
        self.addCleanup(self.server.close)
        self.server.settimeout(3)
        self.server.bind(('127.0.0.1', 0))
        self.server.listen()
        self.target_port = self.server.getsockname()[1]

    def stop_proxy(self):
        self.proxy.terminate()
        _, self.errors = self.proxy.communicate(timeout=5)
        self.assertNotIn(b'ERROR: AddressSanitizer', self.errors, self.errors.decode())

    def ask(self, request):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(request)
            return client.recv(4096)

    def assert_not_dialed(self):
        self.server.settimeout(0.1)
        with self.assertRaises(TimeoutError):
            self.server.accept()

    def test_blocked_over_http_and_socks(self):
        reply = self.ask(f'CONNECT localhost:{self.target_port} HTTP/1.1\r\n\r\n'.encode())
        self.assertTrue(reply.startswith(b'HTTP/1.1 403 '), reply)
        reply = self.ask(f'GET http://LOCALHOST.:{self.target_port}/ HTTP/1.1\r\n\r\n'.encode())
        self.assertTrue(reply.startswith(b'HTTP/1.1 403 '), reply)
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'\x05\x01\x00' + socks_request('localhost', self.target_port))
            self.assertEqual(recv_exact(client, 4), b'\x05\x00\x05\x02')  # 2: not allowed by ruleset
        self.assert_not_dialed()
        # Blocked names are not looked up either.
        reply = self.ask(b'CONNECT sub.blocked.invalid:443 HTTP/1.1\r\n\r\n')
        self.assertTrue(reply.startswith(b'HTTP/1.1 403 '), reply)
        # The line is written as the connection closes, just after the reply.
        deadline = time.monotonic() + 3
        while self.log.read_text().count('result=blocked') < 4 and time.monotonic() < deadline:
            time.sleep(0.02)
        text = self.log.read_text()
        self.assertEqual(text.count('result=blocked'), 4, text)

    def test_other_hosts_pass(self):
        reply = self.ask(f'CONNECT 127.0.0.1:{self.target_port} HTTP/1.1\r\n\r\n'.encode())
        self.assertTrue(reply.startswith(b'HTTP/1.1 200 '), reply)

    def test_sighup_rereads_the_list(self):
        self.deny.write_text('blocked.invalid\n')
        self.proxy.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        reply = self.ask(f'CONNECT localhost:{self.target_port} HTTP/1.1\r\n\r\n'.encode())
        self.assertTrue(reply.startswith(b'HTTP/1.1 200 '), reply)
        # A list that has become unreadable leaves the last one in force.
        self.deny.unlink()
        self.proxy.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        reply = self.ask(b'CONNECT blocked.invalid:443 HTTP/1.1\r\n\r\n')
        self.assertTrue(reply.startswith(b'HTTP/1.1 403 '), reply)
        self.assertEqual(self.proxy.poll(), None)
        self.stop_proxy()
        self.assertIn(b'reread', self.errors)
        self.assertIn(b'cannot open', self.errors)

    def test_missing_deny_file_refused_at_start(self):
        result = subprocess.run([self.binary, '--deny-file', str(Path(self.temp.name) / 'nope')],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'cannot open', result.stderr)


class HeaderTimeoutTests(unittest.TestCase):
    """Idle clients are dropped in every mode. Before, -f never ran the sweep."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-timeout-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build(cls.temp.name, 'proxy', '-DHEADER_TIMEOUT_MS=400')

    def assert_idle_client_dropped(self, port):
        with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
            start = time.monotonic()
            self.assertEqual(client.recv(1), b'')
            self.assertLess(time.monotonic() - start, 3)

    def test_foreground_daemon_mode(self):
        port = free_port()
        proxy = subprocess.Popen([self.binary, '-f', str(port)], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_listening(port)
            self.assert_idle_client_dropped(port)
            # A partial request line is no better than silence.
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.sendall(b'CONNECT example.com:443 HTTP/1.1\r\n')
                self.assertEqual(client.recv(1), b'')
        finally:
            proxy.terminate()
            _, errors = proxy.communicate(timeout=5)
        self.assertNotIn(b'ERROR: AddressSanitizer', errors, errors.decode())

    def test_coprocess_mode(self):
        proxy = subprocess.Popen([self.binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        try:
            self.assert_idle_client_dropped(int(proxy.stdout.readline()))
        finally:
            proxy.terminate()
            _, errors = proxy.communicate(timeout=5)
        self.assertNotIn(b'ERROR: AddressSanitizer', errors, errors.decode())


@unittest.skipUnless(os.environ.get('PROXY_NETWORK_TESTS'), 'set PROXY_NETWORK_TESTS=1')
class NetworkTests(unittest.TestCase):
    """Real names through Android's resolver (resNetworkQuery), not the fakes."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxy-net-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build(cls.temp.name, 'proxy')

    def setUp(self):
        self.proxy = subprocess.Popen([self.binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.addCleanup(self.proxy.communicate, timeout=5)
        self.addCleanup(self.proxy.terminate)
        self.port = int(self.proxy.stdout.readline())

    def test_connect_resolves_real_name(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=15) as client:
            client.sendall(b'CONNECT example.com:80 HTTP/1.1\r\n\r\n')
            self.assertTrue(client.recv(4096).startswith(b'HTTP/1.1 200 '))
            client.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
            self.assertTrue(client.recv(4096).startswith(b'HTTP/1.'))

    def test_nonexistent_name_is_502(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=15) as client:
            client.sendall(b'CONNECT no-such-host.invalid:443 HTTP/1.1\r\n\r\n')
            self.assertTrue(client.recv(4096).startswith(b'HTTP/1.1 502 '))


if __name__ == '__main__':
    unittest.main()
