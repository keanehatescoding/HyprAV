CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
PKG_CONFIG ?= pkg-config

# install target only - PREFIX/SYSCONFDIR/UNITDIR follow the usual
# GNU/systemd conventions so a packager can override them
# (DESTDIR=... for a staged build root, PREFIX=/usr for a distro
# package instead of the /usr/local default, etc.).
PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc/hyprav
UNITDIR     ?= /usr/lib/systemd/system
DESTDIR     ?=

LIBNL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnl-genl-3.0 2>/dev/null)
LIBNL_LIBS   := $(shell $(PKG_CONFIG) --libs libnl-genl-3.0 2>/dev/null)
YARA_CFLAGS  := $(shell $(PKG_CONFIG) --cflags yara 2>/dev/null)
YARA_LIBS    := $(shell $(PKG_CONFIG) --libs yara 2>/dev/null)
# libfuzzy (ssdeep) doesn't ship a pkg-config file - link manually.
FUZZY_LIBS   := -lfuzzy

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
	@if ! echo 'int main(){return 0;}' | $(CC) -x c - -o /tmp/.avd_fuzzy_check $(FUZZY_LIBS) 2>/dev/null; then \
		echo "ERROR: libfuzzy (ssdeep) not found."; \
		echo "  Arch/CachyOS: sudo pacman -S ssdeep"; \
		echo "  Debian/Ubuntu: sudo apt install libfuzzy-dev"; \
		exit 1; \
	fi
	@rm -f /tmp/.avd_fuzzy_check
	$(CC) $(CFLAGS) $(LIBNL_CFLAGS) $(YARA_CFLAGS) -o avd avd.c $(LIBNL_LIBS) $(YARA_LIBS) $(FUZZY_LIBS) -lpthread

clean:
	rm -f avd

# Installs the binary, the systemd unit, and a default rules/corpus
# location under SYSCONFDIR - NOT enabled or started automatically
# (that's a deliberate, separate step: starting a daemon that scans
# and quarantines files system-wide shouldn't be a silent side effect
# of `make install`). ExecStart in packaging/avd.service points at
# these exact paths - keep them in sync if either changes.
install: avd
	install -D -m 0755 avd "$(DESTDIR)$(PREFIX)/bin/avd"
	install -D -m 0644 ../../packaging/avd.service \
		"$(DESTDIR)$(UNITDIR)/avd.service"
	mkdir -p "$(DESTDIR)$(SYSCONFDIR)/rules"
	install -m 0644 ../../rules/*.yar "$(DESTDIR)$(SYSCONFDIR)/rules/"
	install -m 0644 ../../corpus/fuzzy_hashes.txt \
		"$(DESTDIR)$(SYSCONFDIR)/fuzzy_hashes.txt"
	@echo
	@echo "Installed:"
	@echo "  $(DESTDIR)$(PREFIX)/bin/avd"
	@echo "  $(DESTDIR)$(UNITDIR)/avd.service"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/rules/*.yar"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/fuzzy_hashes.txt"
	@echo
	@echo "Not started - review the unit, then:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now avd.service"

.PHONY: clean install
