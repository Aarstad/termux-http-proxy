// Deterministic timeout test: an in-progress connect interrupted by signals.
#define CONNECT_TIMEOUT_MS 80
#define WRITE_TIMEOUT_MS 80
#define connect test_connect
#define poll test_poll
#define main proxy_main
#ifndef PROXY_SOURCE
#define PROXY_SOURCE "../termux-http-proxy.c"
#endif
#include PROXY_SOURCE
#undef main
#undef connect
#undef poll
#include <assert.h>

static int polls;
static int previous_timeout;
int test_connect(int fd, const struct sockaddr *addr, socklen_t len) {
  (void)fd; (void)addr; (void)len;
  errno = EINPROGRESS;
  return -1;
}
int test_poll(struct pollfd *fds, nfds_t count, int timeout) {
  (void)fds; (void)count;
  assert(timeout > 0 && timeout <= CONNECT_TIMEOUT_MS);
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

int main(void) {
  test_backpressure();
  int64_t start = monotonic_ms();
  assert(dial("127.0.0.1", "443") == -1);
  assert(polls >= 2);
  assert(monotonic_ms() - start < 1000);

  // A blocked setup write uses the same fixed deadline despite EINTR.
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
  char buf[4096] = {0};
  while (write(pair[0], buf, sizeof buf) > 0) {}
  assert(errno == EAGAIN || errno == EWOULDBLOCK);
  polls = 0;
  start = monotonic_ms();
  assert(!write_all(pair[0], "x", 1));
  assert(polls >= 2);
  assert(monotonic_ms() - start < 1000);
  close(pair[0]); close(pair[1]);
  return 0;
}
