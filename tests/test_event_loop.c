// Event-loop tests: runs the real proxy loop in a child process with a fake resolver
// and a connect() that can blackhole chosen addresses, then drives it over TCP.
//
// Proves that a stalled lookup no longer blocks other clients, and covers the DNS,
// per-address connect and header deadlines with timings short enough to test.
// Built by tests/test_proxy.py under AddressSanitizer.
#define HEADER_TIMEOUT_MS 300
#define DNS_TIMEOUT_MS 400
#define CONNECT_TIMEOUT_MS 600
#define RESOLUTION_DELAY_MS 100
#include <sys/socket.h>
int test_connect(int fd, const struct sockaddr *addr, socklen_t len);
#define connect test_connect
#define main proxy_main
#ifndef PROXY_SOURCE
#define PROXY_SOURCE "../termux-http-proxy.c"
#endif
#include PROXY_SOURCE
#undef main
#undef connect
#include <assert.h>
#include <sys/wait.h>

// ---- Fakes (run inside the proxy child) ---------------------------------------------

struct fake {
  const char *name;
  int rcode;
  const char *a[3];
  const char *aaaa[3];
  int stall_a, stall_aaaa; // Never answer this query type
};

static const struct fake fakes[] = {
  { "fast.test", 0, { "127.0.0.1" }, { NULL }, 0, 0 },
  { "slow.test", 0, { NULL }, { NULL }, 1, 1 },
  { "nx.test", NS_RCODE_NXDOMAIN, { NULL }, { NULL }, 0, 0 },
  { "v4-slow-v6.test", 0, { "127.0.0.1" }, { NULL }, 0, 1 },
  { "blackhole-first.test", 0, { "192.0.2.1", "127.0.0.1" }, { NULL }, 0, 0 },
  { "all-blackhole.test", 0, { "192.0.2.1", "192.0.2.2" }, { NULL }, 0, 0 },
  { "v6-then-v4.test", 0, { "127.0.0.1" }, { "100::1" }, 0, 0 },
  { "v6-fast-v4-slow.test", 0, { NULL }, { "::1" }, 1, 0 },
  { "empty-v6-v4-slow.test", 0, { NULL }, { NULL }, 1, 0 },
};

// Writer ends of stalled queries and blackholed sockets, held open for the child's life.
static int held[256];
static int nheld;

static void hold(int fd) {
  assert(nheld < (int)(sizeof held / sizeof *held));
  held[nheld++] = fd;
}

static int put16(uint8_t *b, int o, int v) {
  b[o] = (uint8_t)(v >> 8);
  b[o + 1] = (uint8_t)v;
  return o + 2;
}

static int fake_nquery(unsigned netid, const char *name, int ns_class, int ns_type,
                       uint32_t flags) {
  (void)netid; (void)flags;
  assert(ns_class == NS_C_IN && (ns_type == NS_T_A || ns_type == NS_T_AAAA));
  const struct fake *f = NULL;
  for (size_t i = 0; i < sizeof fakes / sizeof *fakes; i++)
    if (strcmp(fakes[i].name, name) == 0) f = &fakes[i];

  int sv[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
  if (f && (ns_type == NS_T_A ? f->stall_a : f->stall_aaaa)) {
    hold(sv[1]);
    return sv[0];
  }

  uint8_t m[512];
  const char *const *ips = f ? (ns_type == NS_T_A ? f->a : f->aaaa) : NULL;
  int an = 0;
  while (ips && an < 3 && ips[an]) an++;
  memset(m, 0, 12);
  put16(m, 2, 0x8180 | (f ? f->rcode : NS_RCODE_NXDOMAIN));
  put16(m, 4, 1);
  put16(m, 6, an);
  int o = 12;
  for (const char *p = name; *p;) {
    const char *dot = strchr(p, '.');
    int l = dot ? (int)(dot - p) : (int)strlen(p);
    m[o++] = (uint8_t)l;
    memcpy(m + o, p, (size_t)l);
    o += l;
    p += l + (dot ? 1 : 0);
  }
  m[o++] = 0;
  o = put16(m, o, ns_type);
  o = put16(m, o, NS_C_IN);
  for (int i = 0; i < an; i++) {
    uint8_t raw[16];
    int rdlen = ns_type == NS_T_A ? 4 : 16;
    assert(inet_pton(ns_type == NS_T_A ? AF_INET : AF_INET6, ips[i], raw) == 1);
    o = put16(m, o, 0xC00C);
    o = put16(m, o, ns_type);
    o = put16(m, o, NS_C_IN);
    o = put16(m, o, 0);
    o = put16(m, o, 60);
    o = put16(m, o, rdlen);
    memcpy(m + o, raw, (size_t)rdlen);
    o += rdlen;
  }
  assert(write(sv[1], m, (size_t)o) == o);
  close(sv[1]);
  return sv[0];
}

static int fake_nresult(int fd, int *rcode, uint8_t *answer, size_t anslen) {
  ssize_t n = read(fd, answer, anslen);
  close(fd);
  if (n < 12) return -EIO;
  *rcode = answer[3] & 0x0F;
  return (int)n;
}

static void fake_cancel(int fd) {
  close(fd);
}

// Addresses in 192.0.2.0/24 (TEST-NET-1) and 100::/64 (discard) never finish
// connecting: the socket is swapped for a Unix socket whose send buffer is full, so
// EPOLLOUT never fires. Everything else connects for real.
int test_connect(int fd, const struct sockaddr *addr, socklen_t len) {
  int blackhole = 0;
  if (addr->sa_family == AF_INET) {
    const uint8_t *ip = (const uint8_t *)&((const struct sockaddr_in *)addr)->sin_addr;
    blackhole = ip[0] == 192 && ip[1] == 0 && ip[2] == 2;
  } else if (addr->sa_family == AF_INET6) {
    const uint8_t *ip = (const uint8_t *)&((const struct sockaddr_in6 *)addr)->sin6_addr;
    blackhole = ip[0] == 0x01 && ip[1] == 0x00;
  }
  if (!blackhole) return connect(fd, addr, len);
  int sv[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0);
  char buf[4096] = {0};
  while (write(sv[0], buf, sizeof buf) > 0) {}
  assert(dup2(sv[0], fd) == fd);
  close(sv[0]);
  hold(sv[1]);
  errno = EINPROGRESS;
  return -1;
}

// ---- Harness (runs in the test process) ---------------------------------------------

static pid_t child;
static int child_stdin = -1;
static int proxy_port;

static void start_proxy(void) {
  int in[2], out[2];
  assert(pipe(in) == 0 && pipe(out) == 0);
  child = fork();
  assert(child >= 0);
  if (child == 0) {
    dup2(in[0], STDIN_FILENO);
    dup2(out[1], STDOUT_FILENO);
    close(in[0]); close(in[1]); close(out[0]); close(out[1]);
    res_nquery = fake_nquery;
    res_nresult = fake_nresult;
    res_cancel = fake_cancel;
    char *argv[] = { "termux-http-proxy", NULL };
    _exit(proxy_main(1, argv));
  }
  close(in[0]);
  close(out[1]);
  child_stdin = in[1];
  char line[16] = {0};
  ssize_t n = read(out[0], line, sizeof line - 1);
  assert(n > 0);
  close(out[0]);
  proxy_port = atoi(line);
  assert(proxy_port > 0);
}

static void stop_proxy(void) {
  close(child_stdin); // The proxy exits when its stdin closes
  int status = 0;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int listener(int family, int *port) {
  int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(fd >= 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_storage ss = {0};
  socklen_t len;
  if (family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    len = sizeof *sin;
  } else {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = in6addr_loopback;
    len = sizeof *sin6;
  }
  if (bind(fd, (struct sockaddr *)&ss, len) < 0 || listen(fd, 16) < 0) {
    close(fd);
    return -1;
  }
  assert(getsockname(fd, (struct sockaddr *)&ss, &len) == 0);
  *port = ntohs(family == AF_INET ? ((struct sockaddr_in *)&ss)->sin_port
                                  : ((struct sockaddr_in6 *)&ss)->sin6_port);
  return fd;
}

static void set_timeout(int fd, int ms) {
  struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

// Connects to the proxy and sends a CONNECT for host:port.
static int request(const char *host, int port) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(fd >= 0);
  struct sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons((uint16_t)proxy_port);
  assert(connect(fd, (struct sockaddr *)&sin, sizeof sin) == 0);
  char buf[256];
  int n = snprintf(buf, sizeof buf, "CONNECT %s:%d HTTP/1.1\r\nHost: x\r\n\r\n", host, port);
  assert(write(fd, buf, (size_t)n) == n);
  return fd;
}

// Reads the status code of the proxy's reply (0 on timeout or EOF).
static int status(int fd, int timeout_ms) {
  set_timeout(fd, timeout_ms);
  char buf[128] = {0};
  size_t n = 0;
  while (n < sizeof buf - 1) {
    ssize_t r = read(fd, buf + n, 1);
    if (r <= 0) break;
    n++;
    if (n >= 4 && memcmp(buf + n - 4, "\r\n\r\n", 4) == 0) break;
  }
  int code = 0;
  if (sscanf(buf, "HTTP/1.1 %d", &code) != 1) return 0;
  return code;
}

// Connects and sends a SOCKS5 greeting (no authentication) and a CONNECT request for
// host:port in one write, as optimistic clients do.
static int socks_request_to(const char *host, int port) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(fd >= 0);
  struct sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons((uint16_t)proxy_port);
  assert(connect(fd, (struct sockaddr *)&sin, sizeof sin) == 0);
  uint8_t buf[300] = { 5, 1, 0, 5, 1, 0, 3 };
  size_t hl = strlen(host), n = 7;
  buf[n++] = (uint8_t)hl;
  memcpy(buf + n, host, hl);
  n += hl;
  buf[n++] = (uint8_t)(port >> 8);
  buf[n++] = (uint8_t)port;
  assert(write(fd, buf, n) == (ssize_t)n);
  return fd;
}

// Reads the method selection and the reply; returns the reply code (-1 on timeout).
static int socks_status(int fd, int timeout_ms) {
  set_timeout(fd, timeout_ms);
  uint8_t buf[12];
  size_t n = 0;
  while (n < sizeof buf) {
    ssize_t r = read(fd, buf + n, sizeof buf - n);
    if (r <= 0) break;
    n += (size_t)r;
  }
  if (n < 12 || buf[0] != 5 || buf[1] != 0 || buf[2] != 5) return -1;
  return buf[3];
}

// The tunnel carries bytes in both directions.
static void check_tunnel(int client, int lfd) {
  set_timeout(lfd, 2000);
  int up = accept(lfd, NULL, NULL);
  assert(up >= 0);
  set_timeout(up, 2000);
  set_timeout(client, 2000);
  char buf[8];
  assert(write(client, "ping", 4) == 4);
  assert(read(up, buf, sizeof buf) == 4 && memcmp(buf, "ping", 4) == 0);
  assert(write(up, "pong", 4) == 4);
  assert(read(client, buf, sizeof buf) == 4 && memcmp(buf, "pong", 4) == 0);
  close(up);
}

static int64_t since(int64_t start) {
  return monotonic_ms() - start;
}

// ---- Tests ---------------------------------------------------------------------------

// The regression this exists for: a lookup that never answers must not hold up
// anyone else. Before, dial() called getaddrinfo() inside the loop.
static void test_stalled_lookup_does_not_block(int lfd, int port) {
  int64_t t0 = monotonic_ms();
  int stuck[8];
  for (int i = 0; i < 8; i++) stuck[i] = request("slow.test", port);
  usleep(50000);
  int64_t t1 = monotonic_ms();
  int ok = request("fast.test", port);
  assert(status(ok, 2000) == 200);
  assert(since(t1) < 200);
  check_tunnel(ok, lfd);
  close(ok);
  // The stalled ones time out, all of them, near DNS_TIMEOUT_MS.
  for (int i = 0; i < 8; i++) {
    assert(status(stuck[i], 3000) == 504);
    close(stuck[i]);
  }
  int64_t took = since(t0);
  assert(took >= DNS_TIMEOUT_MS - 50 && took < DNS_TIMEOUT_MS + 1500);
}

static void test_nxdomain(int port) {
  int64_t t0 = monotonic_ms();
  int fd = request("nx.test", port);
  assert(status(fd, 2000) == 502);
  assert(since(t0) < 200);
  close(fd);
}

// A slow AAAA must not hold up a working A for long: RESOLUTION_DELAY_MS after the A
// answer, the proxy dials what it has instead of waiting out DNS_TIMEOUT_MS.
static void test_partial_answer_is_used(int lfd, int port) {
  int64_t t0 = monotonic_ms();
  int fd = request("v4-slow-v6.test", port);
  assert(status(fd, 3000) == 200);
  int64_t took = since(t0);
  assert(took >= RESOLUTION_DELAY_MS - 10 && took < DNS_TIMEOUT_MS - 100);
  check_tunnel(fd, lfd);
  close(fd);
}

// An answer with no addresses starts no grace period: the proxy keeps waiting for
// the other family, and fails only at DNS_TIMEOUT_MS.
static void test_empty_answer_waits_for_other_family(int port) {
  int64_t t0 = monotonic_ms();
  int fd = request("empty-v6-v4-slow.test", port);
  assert(status(fd, 3000) == 504);
  int64_t took = since(t0);
  assert(took >= DNS_TIMEOUT_MS - 50 && took < DNS_TIMEOUT_MS + 1500);
  close(fd);
}

// A blackholed first address gets its share of the budget, then the next is tried.
static void test_blackholed_address_falls_through(int lfd, int port) {
  int64_t t0 = monotonic_ms();
  int fd = request("blackhole-first.test", port);
  assert(status(fd, 3000) == 200);
  int64_t took = since(t0);
  assert(took >= CONNECT_TIMEOUT_MS / 2 - 50 && took < CONNECT_TIMEOUT_MS);
  check_tunnel(fd, lfd);
  close(fd);
}

static void test_all_blackholed_times_out(int port) {
  int64_t t0 = monotonic_ms();
  int fd = request("all-blackhole.test", port);
  assert(status(fd, 3000) == 504);
  int64_t took = since(t0);
  assert(took >= CONNECT_TIMEOUT_MS - 50 && took < CONNECT_TIMEOUT_MS + 1500);
  close(fd);
}

// IPv4 is tried first, so a blackholed IPv6 address costs nothing when A works.
static void test_ipv4_first(int lfd, int port) {
  int64_t t0 = monotonic_ms();
  int fd = request("v6-then-v4.test", port);
  assert(status(fd, 3000) == 200);
  assert(since(t0) < 200);
  check_tunnel(fd, lfd);
  close(fd);
}

// A client that hangs up mid-lookup is cleaned up and the loop carries on.
static void test_client_gives_up(int lfd, int port) {
  for (int i = 0; i < 20; i++) close(request("slow.test", port));
  usleep(100000);
  int fd = request("fast.test", port);
  assert(status(fd, 2000) == 200);
  check_tunnel(fd, lfd);
  close(fd);
}

// SOCKS5 goes through the same resolve and dial path, with failures reported as
// SOCKS5 reply codes: 4 (host unreachable) for a missing name and for timeouts.
static void test_socks(int lfd, int port) {
  int fd = socks_request_to("fast.test", port);
  assert(socks_status(fd, 2000) == 0);
  check_tunnel(fd, lfd);
  close(fd);

  int64_t t0 = monotonic_ms();
  fd = socks_request_to("nx.test", port);
  assert(socks_status(fd, 2000) == 4);
  assert(since(t0) < 200);
  close(fd);

  t0 = monotonic_ms();
  fd = socks_request_to("all-blackhole.test", port);
  assert(socks_status(fd, 3000) == 4);
  assert(since(t0) >= CONNECT_TIMEOUT_MS - 50);
  close(fd);

  // A stalled lookup holds up neither HTTP nor SOCKS5 clients.
  int stuck = socks_request_to("slow.test", port);
  usleep(50000);
  fd = request("fast.test", port);
  assert(status(fd, 2000) == 200);
  check_tunnel(fd, lfd);
  close(fd);
  assert(socks_status(stuck, 3000) == 4);
  close(stuck);
}

// A client that connects and sends nothing is dropped at HEADER_TIMEOUT_MS.
static void test_header_timeout(void) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons((uint16_t)proxy_port);
  assert(connect(fd, (struct sockaddr *)&sin, sizeof sin) == 0);
  int64_t t0 = monotonic_ms();
  set_timeout(fd, 3000);
  char c;
  assert(read(fd, &c, 1) == 0);
  int64_t took = since(t0);
  assert(took >= HEADER_TIMEOUT_MS - 50 && took < HEADER_TIMEOUT_MS + 1500);
  close(fd);
}

// IPv6 is dialed over IPv6: a literal, and an AAAA answer whose A query stalls,
// which is used RESOLUTION_DELAY_MS later (skipped where ::1 is unavailable).
static void test_ipv6_answer(void) {
  int port;
  int lfd6 = listener(AF_INET6, &port);
  if (lfd6 < 0) {
    fprintf(stderr, "test_event_loop: ::1 unavailable, skipping IPv6 dial\n");
    return;
  }
  int fd = request("[::1]", port);
  assert(status(fd, 2000) == 200);
  check_tunnel(fd, lfd6);
  close(fd);

  int64_t t0 = monotonic_ms();
  fd = request("v6-fast-v4-slow.test", port);
  assert(status(fd, 3000) == 200);
  int64_t took = since(t0);
  assert(took >= RESOLUTION_DELAY_MS - 10 && took < DNS_TIMEOUT_MS - 100);
  check_tunnel(fd, lfd6);
  close(fd);
  close(lfd6);
}

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  start_proxy();
  int port;
  int lfd = listener(AF_INET, &port);
  assert(lfd >= 0);
  test_stalled_lookup_does_not_block(lfd, port);
  test_nxdomain(port);
  test_partial_answer_is_used(lfd, port);
  test_empty_answer_waits_for_other_family(port);
  test_blackholed_address_falls_through(lfd, port);
  test_all_blackholed_times_out(port);
  test_ipv4_first(lfd, port);
  test_client_gives_up(lfd, port);
  test_socks(lfd, port);
  test_header_timeout();
  test_ipv6_answer();
  close(lfd);
  stop_proxy();
  return 0;
}
