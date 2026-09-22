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

`termux-http-proxy` is a native Bionic C daemon that bridges this gap. When outbound HTTP/HTTPS traffic is pointed at this proxy via standard `HTTP_PROXY` / `HTTPS_PROXY` environment variables, HTTP clients issue HTTP `CONNECT` requests for remote hostnames. The proxy resolves the hostnames natively through Android Bionic's system resolver and uses kernel zero-copy `splice(2)` to tunnel traffic directly between the client and the remote destination.

## Highlights

* **Zero-copy:** Forwards stream data between sockets entirely in kernel space via `splice(2)` and circular pipes.
* **Low memory overhead:** ~3MB RSS / ~700KB PSS in production under load.
* **0% idle CPU:** Single-threaded event loop driven by `epoll(7)` with infinite timeout; sleeps deeply in the kernel scheduler between requests.
* **Automatic lifecycle cleanup:** Automatically monitors `stdin` and parent process PID via `timerfd(2)`. Exits immediately when the parent process or shell exits—no orphan processes.
* **Zero dependencies:** Standard C99, links directly against Android Bionic libc.

## Build and Install

```bash
make
make install
```

This installs `termux-http-proxy` into `$PREFIX/bin` (and sets up a compatibility symlink `dns-proxy -> termux-http-proxy`).

## Usage

### Run as a background helper
When started without arguments, `termux-http-proxy` binds to a dynamic loopback port (`127.0.0.1:0`), prints the assigned port number to `stdout`, and waits on `stdin`:

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

### Running with a static port (daemon mode)
```bash
termux-http-proxy --port 18080
```

## Running Tests

Requires Python 3 and a C compiler (`clang` in Termux):

```bash
make test
```

Includes:
* Loopback functional tests under AddressSanitizer (`-fsanitize=address`) testing HTTP headers, tunneling, early payload forwarding, chunked encoding rejection, and teardown.
* Connection deadline and arithmetic unit tests.
* Production memory and RSS/PSS footprint benchmark.

## License

MIT
