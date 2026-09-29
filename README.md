# termux-http-proxy

A high-performance, ultra-lightweight, zero-copy HTTP `CONNECT` and SOCKS5 forward proxy for Android/Termux environments.

## Why this exists

Processes running on Android under non-Bionic runtimes (such as **musl libc**, standard glibc, Alpine Linux binaries, or unpatched Go/Rust binaries) expect standard Linux networking conventions:
* They read `/etc/resolv.conf` to discover DNS resolvers.
* They issue raw UDP queries to port 53.

On Android:
1. `/etc/resolv.conf` does not exist.
2. Direct outbound UDP queries to port 53 are frequently blocked or restricted by cellular carriers and Android firewall policies.
3. Native Android apps and Bionic binaries resolve DNS by asking Android's system resolver daemon.

`termux-http-proxy` is a native Bionic C daemon that bridges this gap. When outbound HTTP/HTTPS traffic is pointed at this proxy via standard `HTTP_PROXY` / `HTTPS_PROXY` environment variables, HTTP clients issue HTTP `CONNECT` requests for remote hostnames. The proxy resolves the hostnames natively through Android's system resolver and uses kernel zero-copy `splice(2)` to tunnel traffic directly between the client and the remote destination.

## Highlights

* **Zero-copy:** Forwards stream data between sockets entirely in kernel space via `splice(2)` and circular pipes.
* **Nothing blocks the loop:** Names are resolved with Android's asynchronous resolver, whose answers arrive on file descriptors that `epoll` watches like any socket; A and AAAA are asked in parallel. Upstream connects are non-blocking. One slow lookup or unreachable host no longer stalls every other tunnel.
* **Per-address connect deadlines:** Each resolved address gets an equal share of the 5s connect budget, so a blackholed IPv6 address cannot eat the time an IPv4 one needs. IPv4 is tried first. Once one of A/AAAA has answered with addresses, the other gets 50ms to catch up (RFC 8305's Resolution Delay) before the proxy dials what it has, so a slow or dropped AAAA query costs 50ms rather than the 10s DNS budget.
* **HTTP and SOCKS5 on one port:** HTTP `CONNECT`, plain HTTP, and SOCKS5 `CONNECT` with names resolved by the proxy (`socks5h://`). The first byte tells them apart. See [SOCKS5](#socks5).
* **Optional authentication:** `--auth-file` requires a token before anything is resolved or dialed, over HTTP and SOCKS5 alike (see [Security](#security)).
* **Deny list:** `--deny-file` refuses listed domains and their subdomains before anything is resolved or dialed; `sv hup` rereads it (see [Deny list](#deny-list)).
* **Connection log:** `--log` writes a line per connection: where it went, which tool asked, bytes each way, how long, and why it failed if it did (see [Logging](#logging)).
* **Low memory overhead:** ~3MB RSS / ~700KB PSS, idle or with tunnels open.
* **0% idle CPU:** Single-threaded event loop driven by `epoll(7)`. With no connection mid-setup, it sleeps with an infinite timeout; deadlines only wake it while something is pending.
* **Automatic lifecycle cleanup:** In coprocess mode it watches `stdin` and the parent PID, and exits as soon as the parent does. No orphan processes.
* **Zero dependencies:** Standard C99, links directly against Android Bionic libc.

## Build and Install

```bash
make
make install
```

This installs `termux-http-proxy` and `termux-http-proxy-ctl` into `$PREFIX/bin`. Earlier copies of this proxy, bundled with claude-code-termux-musl, agy-termux-musl and codex-termux, were called `dns-proxy`.

## Usage

```
termux-http-proxy [--port PORT | PORT] [-f | -d] [--auth-file PATH] [--log PATH]
                  [--deny-file PATH]
```

### Run as a background helper (coprocess mode)
When started without a port, `termux-http-proxy` binds to a dynamic loopback port (`127.0.0.1:0`), prints the assigned port number to `stdout`, and waits on `stdin`:

```bash
# In bash / wrapper scripts:
coproc PROXY { termux-http-proxy; }
read -r PROXY_PORT <&"${PROXY[0]}"

export HTTP_PROXY="http://127.0.0.1:$PROXY_PORT"
export HTTPS_PROXY="http://127.0.0.1:$PROXY_PORT"

# Run your musl / Alpine / Go / Rust binary
./my-musl-app
```

When your script exits or closes the pipe to the proxy's `stdin`, `termux-http-proxy` terminates automatically.

### Run as a shared daemon on a fixed port
```bash
termux-http-proxy --port 18080          # detaches
termux-http-proxy -f 18080              # stays in the foreground, for runit/termux-services
```

A runit service (`$PREFIX/var/service/termux-http-proxy/run`) looks like:

```sh
#!/data/data/com.termux/files/usr/bin/sh
exec 2>&1
TOKEN=/data/data/com.termux/files/home/.config/termux-http-proxy/token
mkdir -p "${TOKEN%/*}" && chmod 700 "${TOKEN%/*}"
exec /data/data/com.termux/files/usr/bin/termux-http-proxy -f 18080 --auth-file "$TOKEN"
```

`termux-http-proxy-ctl {start|stop|restart|status}` manages the daemon on port 18080:
through `sv` when that service exists, otherwise as a detached process.
`termux-http-proxy-ctl check` reports whether clients can use it: listening, a usable
token file, requests without the token refused, and one with the token reaching the
internet (`--local` skips that last, network-dependent step). It exits non-zero on a
problem, so startup scripts can act on it.

## Security

Android's loopback interface is **shared by every app on the device**. Without authentication, any installed app can reach `127.0.0.1:PORT` and use the proxy to connect anywhere, including other apps' localhost services, with no network permission of its own. A fixed-port daemon is the obvious target, but a coprocess port can be found by scanning too.

`--auth-file PATH` closes this:

* The proxy requires `Proxy-Authorization: Basic ...` whose password is the token in `PATH`. The username is ignored. Anything else gets `407 Proxy Authentication Required`, **before** any name is resolved or any connection is made.
* If `PATH` does not exist, it is created with a random 128-bit token and mode `0600`. Keep it under Termux's private data directory, which other apps cannot read.
* A token file readable by other users is refused at startup (`chmod 600` it), as are tokens under 16 characters. Errors are reported before the daemon detaches, so a bad file never becomes a silently open proxy.

Clients pass the token in the proxy URL, which curl, Bun and Node all turn into the header:

```bash
TOKEN=$(cat ~/.config/termux-http-proxy/token)
export HTTPS_PROXY="http://proxy:$TOKEN@127.0.0.1:18080"
export HTTP_PROXY="$HTTPS_PROXY"
```

The header is stripped from plain-HTTP requests before they are forwarded.

SOCKS5 clients authenticate with username/password (RFC 1929), again with any username and the token as the password. With `--auth-file`, a SOCKS5 client that does not offer that method is turned away before it can send a request.

## SOCKS5

The same port speaks SOCKS5 (RFC 1928). Only the `CONNECT` command is supported: `BIND` and `UDP ASSOCIATE` get reply 7 (command not supported). Targets can be IPv4, IPv6 or a domain name; use `socks5h://` so the proxy resolves names through Android's resolver, which is the reason this proxy exists:

```bash
curl -x "socks5h://proxy:$TOKEN@127.0.0.1:18080" https://example.com
export ALL_PROXY="socks5h://proxy:$TOKEN@127.0.0.1:18080"
```

Clients may send their greeting, credentials and request without waiting for the replies. Failures come back as SOCKS5 reply codes: 4 (host unreachable) for names that do not resolve and for timeouts, 5 for a refused connection, 3 when there is no route to the address family.

## Deny list

`--deny-file PATH` refuses connections to the domains listed in `PATH`, and to all their subdomains, before any lookup or connection: HTTP clients get `403 Forbidden`, SOCKS5 clients reply 2 (not allowed by ruleset), and the log says `result=blocked`.

```
# ~/.config/termux-http-proxy/deny
datadoghq.com        # also blocks http-intake.logs.us5.datadoghq.com
*.example.net        # "*." and a leading "." are optional
```

One domain per line; `#` starts a comment; matching ignores case and a trailing dot. `SIGHUP` rereads the file (`sv hup termux-http-proxy` under runit), and a file that has become unreadable leaves the previous list in force; at startup a missing file is an error.

It matches the name a client asks for. A client that connects to an IP address directly, or uses its own DNS-over-HTTPS, is not caught by a domain rule.

## Logging

`--log PATH` appends a line per connection to `PATH` (created with mode `0600`), written when the connection ends:

```
2026-09-29 10:17:56 socks5 example.com:443 user=claude addr=172.66.147.243 result=ok up=1921 down=6577 time=0.085s
2026-09-29 10:17:56 connect evil.test:443 user=- addr=- result=auth-failed up=0 down=0 time=0.001s
2026-09-29 10:17:56 socks5 no-such-host.invalid:443 user=claude addr=- result=nxdomain up=0 down=0 time=0.007s
```

* **Protocol:** `connect`, `http` or `socks5`.
* **`user`:** the username the client authenticated with. Since any username is accepted, a launcher can put its own name in the proxy URL (`http://claude:$TOKEN@…`) to show up in the log.
* **`addr`:** the address actually connected to.
* **`up`/`down`:** bytes from the client to the target and back.
* **`result`:** `ok`, or `auth-failed`, `nxdomain`, `no-address`, `dns-timeout`, `refused`, `unreachable`, `connect-timeout`, `bad-request`, `unsupported`, `header-timeout`, `client-left`, and the like.

Only the host and port are logged, never a plain-HTTP path or query, and client-supplied text is sanitised so it cannot forge fields or lines. A tunnel is logged when it closes, so a long-lived connection appears once it ends.

`--log -` writes to stderr without timestamps, for a supervisor that adds its own (runit's `svlogd -tt`): add it to the service's `run` line and read the log with `tail -f $PREFIX/var/log/sv/termux-http-proxy/current`. It needs `-f` or coprocess mode, since a detached daemon has no stderr.

## How resolution works

Android exposes an asynchronous DNS API (`android_res_nquery`, API 29+) that goes through the same system resolver as `getaddrinfo`, so Private DNS and per-network servers apply, but returns a file descriptor instead of blocking.

The proxy calls the implementation directly: `resNetworkQuery` in `libnetd_client.so`. The public `android_res_nquery` in `libandroid.so` is only a 40-byte wrapper around it, and loading `libandroid.so` pulls in ~1,200 more mapped objects, taking the proxy from 3MB to 45MB RSS. `libc` already has `libnetd_client.so` loaded for `getaddrinfo`, so opening it costs nothing. (A bare `dlopen("libandroid.so")` would also find Termux's `libandroid-stub` package first, which lacks these functions.)

`resNetworkQuery` is not part of the public NDK. If it cannot be loaded, the proxy falls back to blocking `getaddrinfo` and behaves as older versions did.

Literal IPv4/IPv6 addresses (`[::1]:443` included) and `localhost` are used without a lookup.

## Running Tests

Requires Python 3 and a C compiler (`clang` in Termux):

```bash
make test            # everything below, plus the memory benchmark
make test-network    # also resolves real names through Android's resolver
```

All builds happen in temporary directories under AddressSanitizer (`-fsanitize=address`):

* **`tests/test_proxy.py`** — loopback functional tests: HTTP header rewriting, tunneling, early payload forwarding, chunked encoding rejection, backpressure and teardown, `localhost` and bracketed IPv6 targets, malformed targets, SOCKS5 (pipelined and byte-at-a-time handshakes, every address type, reply codes, unsupported commands), authentication over HTTP and SOCKS5 (including real `curl` with credentials in `http://` and `socks5h://` proxy URLs), the connection log (byte counts, refusals, nothing secret logged), the deny list (HTTP and SOCKS5, no lookup for blocked names, live reload), argument handling, header timeouts in both coprocess and `-f` mode, and a release-build footprint limit. It also builds and runs the C suites below.
* **`tests/test_units.c`** — DNS answer parsing (compressed names, CNAME chains, every truncation of a valid message, hostile counts), host/port parsing, credential checks, log sanitising, deny-list matching, SOCKS5 replies, token-file creation and refusal, write deadlines under `EINTR`, and tunnel backpressure.
* **`tests/test_event_loop.c`** — runs the real event loop with a fake resolver and a `connect()` that can blackhole chosen addresses: a stalled lookup does not block other clients, NXDOMAIN, a partial A/AAAA answer is dialed after the resolution delay (and an empty one starts no delay), a blackholed address falls through to the next, all-blackholed times out with `504`, IPv4-first ordering, clients hanging up mid-lookup, IPv6 dialing, and SOCKS5 through the same paths.
* **`tests/measure_memory.py`** — RSS/PSS footprint benchmark, optionally against a Bun implementation (`--bun-js`).

## Used by

Each of these bundles a copy of `termux-http-proxy.c` for its own fallback proxy, and
shares the daemon on port 18080 when it is running:

* [claude-code-termux-musl](https://github.com/Aarstad/claude-code-termux-musl) — Anthropic's Claude Code
* [codex-termux](https://github.com/Aarstad/codex-termux) — OpenAI's Codex CLI
* [agy-termux-musl](https://github.com/Aarstad/agy-termux-musl) — Google's Antigravity CLI

## License

MIT
