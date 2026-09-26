# termux-http-proxy

A high-performance, ultra-lightweight, zero-copy HTTP `CONNECT` forward proxy for Android/Termux environments.

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
* **Optional authentication:** `--auth-file` requires a token before anything is resolved or dialed (see [Security](#security)).
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
termux-http-proxy [--port PORT | PORT] [-f | -d] [--auth-file PATH]
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

* **`tests/test_proxy.py`** — loopback functional tests: HTTP header rewriting, tunneling, early payload forwarding, chunked encoding rejection, backpressure and teardown, `localhost` and bracketed IPv6 targets, malformed targets, authentication (including real `curl` with credentials in the proxy URL), argument handling, header timeouts in both coprocess and `-f` mode, and a release-build footprint limit. It also builds and runs the C suites below.
* **`tests/test_units.c`** — DNS answer parsing (compressed names, CNAME chains, every truncation of a valid message, hostile counts), host/port parsing, credential checks, token-file creation and refusal, write deadlines under `EINTR`, and tunnel backpressure.
* **`tests/test_event_loop.c`** — runs the real event loop with a fake resolver and a `connect()` that can blackhole chosen addresses: a stalled lookup does not block other clients, NXDOMAIN, a partial A/AAAA answer is dialed after the resolution delay (and an empty one starts no delay), a blackholed address falls through to the next, all-blackholed times out with `504`, IPv4-first ordering, clients hanging up mid-lookup, and IPv6 dialing.
* **`tests/measure_memory.py`** — RSS/PSS footprint benchmark, optionally against a Bun implementation (`--bun-js`).

## Used by

Each of these bundles a copy of `termux-http-proxy.c` for its own fallback proxy, and
shares the daemon on port 18080 when it is running:

* [claude-code-termux-musl](https://github.com/Aarstad/claude-code-termux-musl) — Anthropic's Claude Code
* [codex-termux](https://github.com/Aarstad/codex-termux) — OpenAI's Codex CLI
* [agy-termux-musl](https://github.com/Aarstad/agy-termux-musl) — Google's Antigravity CLI

## License

MIT
