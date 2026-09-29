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

# The new file is renamed over the old one rather than written in place, so a proxy
# that is running keeps its executable and the replacement is used on its next start.
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/.$(TARGET).new
	mv -f $(DESTDIR)$(BINDIR)/.$(TARGET).new $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 755 $(TARGET)-ctl $(DESTDIR)$(BINDIR)/$(TARGET)-ctl
	install -m 755 $(TARGET)-blocklists $(DESTDIR)$(BINDIR)/$(TARGET)-blocklists

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)-ctl $(DESTDIR)$(BINDIR)/$(TARGET)-blocklists

# test_proxy.py also builds and runs the C suites (tests/test_units.c, tests/test_event_loop.c).
test:
	python3 tests/test_proxy.py
	python3 tests/measure_memory.py

# Adds tests that resolve real names through Android's resolver.
test-network:
	PROXY_NETWORK_TESTS=1 python3 tests/test_proxy.py

clean:
	rm -f $(TARGET)
