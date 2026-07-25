CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
PKG_CONFIG ?= pkg-config

LIBNL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnl-genl-3.0 2>/dev/null)
LIBNL_LIBS   := $(shell $(PKG_CONFIG) --libs libnl-genl-3.0 2>/dev/null)
YARA_CFLAGS  := $(shell $(PKG_CONFIG) --cflags yara 2>/dev/null)
YARA_LIBS    := $(shell $(PKG_CONFIG) --libs yara 2>/dev/null)

avd: avd.c ../../av/netlink_proto.h
	@if [ -z "$(LIBNL_LIBS)" ]; then \
		echo "ERROR: libnl-genl-3.0 not found via pkg-config."; \
		echo "  Arch/CachyOS: sudo pacman -S libnl"; \
		echo "  Debian/Ubuntu: sudo apt install libnl-genl-3-dev"; \
		exit 1; \
	fi
	@if [ -z "$(YARA_LIBS)" ]; then \
		echo "ERROR: yara not found via pkg-config."; \
		echo "  Arch/CachyOS: sudo pacman -S yara"; \
		echo "  Debian/Ubuntu: sudo apt install libyara-dev"; \
		exit 1; \
	fi
	$(CC) $(CFLAGS) $(LIBNL_CFLAGS) $(YARA_CFLAGS) -o avd avd.c $(LIBNL_LIBS) $(YARA_LIBS)

clean:
	rm -f avd

.PHONY: clean
