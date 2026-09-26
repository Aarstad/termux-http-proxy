PREFIX ?= /data/data/com.termux/files/usr
BINDIR ?= $(PREFIX)/bin
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic

TARGET = termux-http-proxy
SRC = termux-http-proxy.c

.PHONY: all clean test test-network install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	ln -sf $(TARGET) $(DESTDIR)$(BINDIR)/dns-proxy

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(BINDIR)/dns-proxy

# test_proxy.py also builds and runs the C suites (tests/test_units.c, tests/test_event_loop.c).
test:
	python3 tests/test_proxy.py
	python3 tests/measure_memory.py

# Adds tests that resolve real names through Android's resolver.
test-network:
	PROXY_NETWORK_TESTS=1 python3 tests/test_proxy.py

clean:
	rm -f $(TARGET)
