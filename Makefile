PREFIX ?= /data/data/com.termux/files/usr
BINDIR ?= $(PREFIX)/bin
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic

TARGET = termux-http-proxy
SRC = termux-http-proxy.c

.PHONY: all clean test install uninstall

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

test:
	python3 tests/test_proxy.py
	$(CC) -Wall -Wextra -O2 -o test_deadlines tests/test_deadlines.c && ./test_deadlines && rm -f test_deadlines
	python3 tests/measure_memory.py

clean:
	rm -f $(TARGET) test_deadlines
