// Unit tests for the proxy's internals: tunnel backpressure, setup write deadlines,
// DNS answer parsing, host:port parsing, Proxy-Authorization checks and token files.
// Built by tests/test_proxy.py under AddressSanitizer.
#define WRITE_TIMEOUT_MS 80
// <poll.h> first, so the real poll() is declared before the proxy's calls are renamed.
#include <poll.h>
int test_poll(struct pollfd *fds, nfds_t count, int timeout);
#define poll test_poll
#define main proxy_main
#ifndef PROXY_SOURCE
#define PROXY_SOURCE "../termux-http-proxy.c"
#endif
#include PROXY_SOURCE
#undef main
#undef poll
#include <assert.h>

// When set, poll() reports EINTR after a short sleep, to check that write deadlines
// keep shrinking across interruptions instead of restarting.
static int fake_eintr;
static int polls;
static int previous_timeout;
int test_poll(struct pollfd *fds, nfds_t count, int timeout) {
  if (!fake_eintr) return poll(fds, count, timeout);
  assert(timeout > 0 && timeout <= WRITE_TIMEOUT_MS);
  if (polls++) assert(timeout < previous_timeout);
  previous_timeout = timeout;
  usleep(20000);
  errno = EINTR;
  return -1;
}

// Check actual epoll readiness while an upstream socket is full, then ensure a
// fatal close releases both directions even with buffered data.
static void test_backpressure(void) {
  int client[2], upstream[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, client) == 0);
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, upstream) == 0);
  epfd = epoll_create1(EPOLL_CLOEXEC);
  assert(epfd >= 0);
  struct conn *c = conn_new(client[0]), *u = conn_new(upstream[0]);
  assert(c && u);
  assert(arm(c) == 0 && arm(u) == 0);
  c->peer = u->fd; u->peer = c->fd;
  struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP };
  ev.data.fd = c->fd;
  assert(epoll_ctl(epfd, EPOLL_CTL_ADD, c->fd, &ev) == 0);
  ev.data.fd = u->fd;
  assert(epoll_ctl(epfd, EPOLL_CTL_ADD, u->fd, &ev) == 0);
  char buf[4096] = {0};
  while (write(u->fd, buf, sizeof buf) > 0) {}
  assert(write(client[1], buf, sizeof buf) == sizeof buf);
  assert(pump(c));
  assert(c->want_out && c->inflight > 0);
  // More unread data must not cause a busy loop while the pipe is blocked.
  assert(write(client[1], buf, sizeof buf) == sizeof buf);
  assert(epoll_wait(epfd, &ev, 1, 30) == 0);
  int cfd = c->fd, ufd = u->fd;
  conn_close(u);
  assert(!conn_get(cfd) && !conn_get(ufd));
  close(client[1]); close(upstream[1]); close(epfd);
}

// A blocked setup write uses one fixed deadline despite EINTR.
static void test_write_deadline(void) {
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
  char buf[4096] = {0};
  while (write(pair[0], buf, sizeof buf) > 0) {}
  assert(errno == EAGAIN || errno == EWOULDBLOCK);
  fake_eintr = 1;
  polls = 0;
  int64_t start = monotonic_ms();
  assert(!write_all(pair[0], "x", 1));
  assert(polls >= 2);
  assert(monotonic_ms() - start < 1000);
  fake_eintr = 0;
  close(pair[0]); close(pair[1]);
}

// ---- DNS messages ----------------------------------------------------------------------

static int w16(uint8_t *b, int o, int v) {
  b[o] = (uint8_t)(v >> 8);
  b[o + 1] = (uint8_t)v;
  return o + 2;
}

static int wname(uint8_t *b, int o, const char *name) {
  while (*name) {
    const char *dot = strchr(name, '.');
    int l = dot ? (int)(dot - name) : (int)strlen(name);
    b[o++] = (uint8_t)l;
    memcpy(b + o, name, (size_t)l);
    o += l;
    name += l + (dot ? 1 : 0);
  }
  b[o++] = 0;
  return o;
}

// Header plus one question; returns the offset after the question.
static int question(uint8_t *b, int an, const char *qname, int qtype) {
  memset(b, 0, 12);
  w16(b, 0, 0x1234);
  w16(b, 2, 0x8180);
  w16(b, 4, 1);
  w16(b, 6, an);
  int o = wname(b, 12, qname);
  o = w16(b, o, qtype);
  return w16(b, o, NS_C_IN);
}

// A resource record whose owner name is a compression pointer to offset ptr.
static int rr(uint8_t *b, int o, int ptr, int type, int class, const void *rdata, int rdlen) {
  o = w16(b, o, 0xC000 | ptr);
  o = w16(b, o, type);
  o = w16(b, o, class);
  o = w16(b, o, 0);
  o = w16(b, o, 60);
  o = w16(b, o, rdlen);
  memcpy(b + o, rdata, (size_t)rdlen);
  return o + rdlen;
}

static struct setup *fresh(uint16_t port) {
  struct setup *su = setup_new();
  assert(su);
  su->port = port;
  return su;
}

static void expect_v4(struct setup *su, int i, const char *ip, uint16_t port) {
  struct sockaddr_in *sin = (struct sockaddr_in *)&su->addr[i];
  char got[INET_ADDRSTRLEN];
  assert(sin->sin_family == AF_INET);
  assert(su->addr_len[i] == sizeof *sin);
  assert(inet_ntop(AF_INET, &sin->sin_addr, got, sizeof got));
  assert(strcmp(got, ip) == 0);
  assert(ntohs(sin->sin_port) == port);
}

static void test_parse_answer(void) {
  uint8_t m[2048];
  const uint8_t ip1[4] = {93, 184, 215, 14}, ip2[4] = {1, 2, 3, 4}, ip3[4] = {5, 6, 7, 8};

  // Plain A answer, owner name compressed to the question.
  struct setup *su = fresh(8443);
  int n = question(m, 1, "example.com", NS_T_A);
  n = rr(m, n, 12, NS_T_A, NS_C_IN, ip1, 4);
  assert(parse_answer(m, n, NS_T_A, su) == 1);
  expect_v4(su, 0, "93.184.215.14", 8443);
  setup_free(su);

  // CNAME chain: www -> edge.example.net, whose two A records point at the CNAME target.
  su = fresh(443);
  n = question(m, 3, "www.example.com", NS_T_A);
  uint8_t target[64];
  int tlen = wname(target, 0, "edge.example.net");
  int cname_rdata = n + 12; // owner pointer(2) type(2) class(2) ttl(4) rdlen(2)
  n = rr(m, n, 12, 5 /* CNAME */, NS_C_IN, target, tlen);
  n = rr(m, n, cname_rdata, NS_T_A, NS_C_IN, ip2, 4);
  n = rr(m, n, cname_rdata, NS_T_A, NS_C_IN, ip3, 4);
  assert(parse_answer(m, n, NS_T_A, su) == 2);
  expect_v4(su, 0, "1.2.3.4", 443);
  expect_v4(su, 1, "5.6.7.8", 443);
  setup_free(su);

  // AAAA, alongside records that must be ignored: wrong class, wrong length, wrong type.
  su = fresh(443);
  uint8_t v6[16];
  inet_pton(AF_INET6, "2001:db8::1", v6);
  n = question(m, 4, "example.com", NS_T_AAAA);
  n = rr(m, n, 12, NS_T_AAAA, 3 /* CH */, v6, 16);
  n = rr(m, n, 12, NS_T_AAAA, NS_C_IN, v6, 4);
  n = rr(m, n, 12, NS_T_A, NS_C_IN, ip1, 4);
  n = rr(m, n, 12, NS_T_AAAA, NS_C_IN, v6, 16);
  assert(parse_answer(m, n, NS_T_AAAA, su) == 1);
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&su->addr[0];
  assert(sin6->sin6_family == AF_INET6 && su->addr_len[0] == sizeof *sin6);
  assert(memcmp(&sin6->sin6_addr, v6, 16) == 0 && ntohs(sin6->sin6_port) == 443);
  setup_free(su);

  // Every truncation of a valid message parses without reading past the end (ASan
  // enforces it), never yields more than the full message, and never a partial record.
  n = question(m, 2, "example.com", NS_T_A);
  n = rr(m, n, 12, NS_T_A, NS_C_IN, ip1, 4);
  n = rr(m, n, 12, NS_T_A, NS_C_IN, ip2, 4);
  for (int cut = 0; cut <= n; cut++) {
    uint8_t *copy = malloc((size_t)(cut ? cut : 1));
    memcpy(copy, m, (size_t)cut);
    su = fresh(1);
    int got = parse_answer(copy, cut, NS_T_A, su);
    assert(got >= 0 && got <= 2);
    assert(cut == n ? got == 2 : got < 2);
    setup_free(su);
    free(copy);
  }

  // Hostile counts and a reserved label type stop parsing cleanly.
  n = question(m, 0, "example.com", NS_T_A);
  w16(m, 6, 0xFFFF);
  su = fresh(1);
  assert(parse_answer(m, n, NS_T_A, su) == 0);
  m[12] = 0x80; // Reserved 10xxxxxx label
  assert(parse_answer(m, n, NS_T_A, su) == 0);
  setup_free(su);

  // More records than MAX_ADDRS are capped, not overflowed.
  su = fresh(1);
  n = question(m, 40, "example.com", NS_T_A);
  for (int i = 0; i < 40; i++) n = rr(m, n, 12, NS_T_A, NS_C_IN, ip2, 4);
  assert(parse_answer(m, n, NS_T_A, su) == MAX_ADDRS);
  assert(su->naddr == MAX_ADDRS);
  setup_free(su);
}

static void test_literals(void) {
  struct setup *su = fresh(80);
  strcpy(su->host, "10.0.0.1");
  assert(add_literal(su) && su->naddr == 1);
  expect_v4(su, 0, "10.0.0.1", 80);
  setup_free(su);

  su = fresh(80);
  strcpy(su->host, "::1");
  assert(add_literal(su) && su->naddr == 1 && su->addr[0].ss_family == AF_INET6);
  setup_free(su);

  su = fresh(80);
  strcpy(su->host, "LocalHost");
  assert(add_literal(su) && su->naddr == 2);
  expect_v4(su, 0, "127.0.0.1", 80);
  assert(su->addr[1].ss_family == AF_INET6);
  setup_free(su);

  su = fresh(80);
  strcpy(su->host, "example.com");
  assert(!add_literal(su) && su->naddr == 0);
  setup_free(su);
}

static void check_split(const char *in, int ok, const char *host, uint16_t port) {
  char buf[512], got[256];
  uint16_t p = 0;
  snprintf(buf, sizeof buf, "%s", in);
  int rc = split_host_port(buf, 443, got, sizeof got, &p);
  if (!ok) { assert(rc == -1); return; }
  assert(rc == 0);
  assert(strcmp(got, host) == 0);
  assert(p == port);
}

static void test_split_host_port(void) {
  check_split("example.com:8443", 1, "example.com", 8443);
  check_split("example.com", 1, "example.com", 443);
  check_split("[::1]:8080", 1, "::1", 8080);
  check_split("[::1]", 1, "::1", 443);
  check_split("::1", 1, "::1", 443); // Bare IPv6: not host:port
  check_split("example.com:0", 0, NULL, 0);
  check_split("example.com:65536", 0, NULL, 0);
  check_split("example.com:https", 0, NULL, 0);
  check_split("example.com:", 0, NULL, 0);
  check_split("[::1", 0, NULL, 0);
  check_split("[::1]x", 0, NULL, 0);
  check_split("", 0, NULL, 0);
  char longname[400];
  memset(longname, 'a', sizeof longname - 1);
  longname[sizeof longname - 1] = 0;
  check_split(longname, 0, NULL, 0);
}

// ---- Authentication ------------------------------------------------------------------

static void b64(const char *in, char *out) {
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t n = strlen(in), o = 0;
  for (size_t i = 0; i < n; i += 3) {
    uint32_t v = (uint32_t)(unsigned char)in[i] << 16;
    if (i + 1 < n) v |= (uint32_t)(unsigned char)in[i + 1] << 8;
    if (i + 2 < n) v |= (unsigned char)in[i + 2];
    out[o++] = tbl[v >> 18 & 63];
    out[o++] = tbl[v >> 12 & 63];
    out[o++] = i + 1 < n ? tbl[v >> 6 & 63] : '=';
    out[o++] = i + 2 < n ? tbl[v & 63] : '=';
  }
  out[o] = 0;
}

static int basic(const char *userpass, const char *scheme) {
  char enc[512], value[600];
  b64(userpass, enc);
  snprintf(value, sizeof value, "%s%s", scheme, enc);
  return credentials_ok(value, strlen(value));
}

static void test_credentials(void) {
  strcpy(auth_token, "0123456789abcdef0123");
  auth_len = strlen(auth_token);
  assert(basic("proxy:0123456789abcdef0123", "Basic "));
  assert(basic(":0123456789abcdef0123", "Basic "));        // Username is ignored
  assert(basic("x:0123456789abcdef0123", "bAsIc   "));      // Scheme is case-insensitive
  assert(!basic("proxy:0123456789abcdef012", "Basic "));   // Prefix of the token
  assert(!basic("proxy:0123456789abcdef01234", "Basic ")); // Token plus one
  assert(!basic("proxy:0123456789abcdef0124", "Basic "));  // Same length, wrong
  assert(!basic("0123456789abcdef0123", "Basic "));        // No colon
  assert(!basic("0123456789abcdef0123:", "Basic "));       // Token as the username
  assert(!basic("u:0123456789abcdef0123:x", "Basic "));    // Colon belongs to the password
  assert(!basic("proxy:0123456789abcdef0123", "Bearer "));
  assert(!credentials_ok("Basic !!!!", 10));
  assert(!credentials_ok("Basic", 5));
  // Trailing whitespace and a stray CR are tolerated.
  char enc[256], value[300];
  b64("p:0123456789abcdef0123", enc);
  snprintf(value, sizeof value, "Basic %s \r", enc);
  assert(credentials_ok(value, strlen(value)));
  auth_len = 0;
  auth_token[0] = 0;
}

static void test_find_header(void) {
  const char *h = "Host: example.com\r\nPROXY-AUTHORIZATION:   Basic abc\r\nX-Last: tail";
  size_t len = 0;
  const char *v = find_header(h, (int)strlen(h), "proxy-authorization:", &len);
  assert(v && len == 9 && strncmp(v, "Basic abc", 9) == 0);
  v = find_header(h, (int)strlen(h), "x-last:", &len);
  assert(v && len == 4 && strncmp(v, "tail", 4) == 0);
  assert(!find_header(h, (int)strlen(h), "cookie:", &len));
  // A header name is only matched at the start of a line.
  const char *h2 = "X-Note: proxy-authorization: nope";
  assert(!find_header(h2, (int)strlen(h2), "proxy-authorization:", &len));
}

static void write_file(const char *path, const char *text, mode_t mode) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
  assert(fd >= 0);
  assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
  assert(fchmod(fd, mode) == 0);
  close(fd);
}

static void test_token_file(void) {
  char dir[256], path[300];
  const char *tmp = getenv("TMPDIR");
  snprintf(dir, sizeof dir, "%s/proxy-token-XXXXXX", tmp ? tmp : "/tmp");
  assert(mkdtemp(dir));
  snprintf(path, sizeof path, "%s/token", dir);

  // Missing: created with a random 32-hex-digit token, mode 0600, and reused afterwards.
  assert(load_token(path) == 0);
  assert(auth_len == 32);
  for (size_t i = 0; i < auth_len; i++) assert(strchr("0123456789abcdef", auth_token[i]));
  struct stat st;
  assert(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
  char first[TOKEN_MAX];
  strcpy(first, auth_token);
  assert(load_token(path) == 0 && strcmp(first, auth_token) == 0);

  // Readable by others: refused.
  write_file(path, "0123456789abcdef0123\n", 0644);
  auth_len = 0;
  assert(load_token(path) == -1 && auth_len == 0);

  // Trailing newline stripped.
  write_file(path, "0123456789abcdef0123\r\n", 0600);
  assert(load_token(path) == 0 && auth_len == 20 && strcmp(auth_token, "0123456789abcdef0123") == 0);

  // Too short, or containing whitespace: refused.
  auth_len = 0;
  write_file(path, "short\n", 0600);
  assert(load_token(path) == -1 && auth_len == 0);
  write_file(path, "0123456789 abcdef0123\n", 0600);
  assert(load_token(path) == -1 && auth_len == 0);

  unlink(path);
  rmdir(dir);
  auth_token[0] = 0;
}

int main(void) {
  test_backpressure();
  test_write_deadline();
  test_parse_answer();
  test_literals();
  test_split_host_port();
  test_credentials();
  test_find_header();
  test_token_file();
  return 0;
}
