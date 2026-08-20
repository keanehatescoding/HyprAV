CC ?= gcc
CXX ?= g++
CFLAGS ?= -Wall -Wextra -O2
CXXFLAGS ?= -Wall -Wextra -O2
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
# libtlsh doesn't ship a pkg-config file either (confirmed against the
# actual distro package, not assumed) - same manual-link-test approach
# as FUZZY_LIBS below. Unlike libfuzzy, libtlsh's only public API is a
# C++ class (see tlsh_shim.h) - the link-test below is a C++ compile,
# not C, since that's genuinely what's needed to use it at all.
TLSH_LIBS    := -ltlsh
# The header install PATH differs by distro too, confirmed the hard
# way (a real CI failure, not assumed): Arch/CachyOS's `tlsh` package
# puts tlsh.h under /usr/include/tlsh/, but Debian/Ubuntu's
# libtlsh-dev installs it flat at /usr/include/tlsh.h. tlsh_shim.cpp
# includes the flat name (<tlsh.h>) to match Ubuntu directly; this
# extra -I is what makes that same flat include ALSO resolve on
# Arch/CachyOS - harmless no-op there if this exact directory ever
# stopped existing, since an -I for a nonexistent directory is
# silently ignored by both gcc and clang, not an error.
TLSH_CFLAGS  := -I/usr/include/tlsh

avd: avd.o tlsh_shim.o
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
	@# mktemp + trap, not a fixed /tmp/.avd_fuzzy_check path: a
	@# predictable world-writable-directory path is a classic
	@# symlink-planting target - another local user (or a concurrent
	@# `make` run) could pre-create a symlink there pointing anywhere,
	@# and if this ever runs privileged (e.g. under `sudo make
	@# install`, which depends on this same rule), the compiler
	@# following that symlink would overwrite an arbitrary
	@# root-owned file with a two-line test program. mktemp's
	@# XXXXXX gives an unpredictable name; the trap cleans it up
	@# even on a failed/interrupted probe.
	@tmp=$$(mktemp "$${TMPDIR:-/tmp}/.avd_fuzzy_check.XXXXXX") || exit 1; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	if ! echo 'int main(){return 0;}' | $(CC) -x c - -o "$$tmp" $(FUZZY_LIBS) 2>/dev/null; then \
		echo "ERROR: libfuzzy (ssdeep) not found."; \
		echo "  Arch/CachyOS: sudo pacman -S ssdeep"; \
		echo "  Debian/Ubuntu: sudo apt install libfuzzy-dev"; \
		exit 1; \
	fi
	@tmp=$$(mktemp "$${TMPDIR:-/tmp}/.avd_tlsh_check.XXXXXX") || exit 1; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	if ! echo 'int main(){return 0;}' | $(CXX) -x c++ - -o "$$tmp" $(TLSH_LIBS) 2>/dev/null; then \
		echo "ERROR: libtlsh not found."; \
		echo "  Arch/CachyOS: sudo pacman -S tlsh"; \
		echo "  Debian/Ubuntu: sudo apt install libtlsh-dev"; \
		exit 1; \
	fi
	$(CXX) -o avd avd.o tlsh_shim.o $(LIBNL_LIBS) $(YARA_LIBS) $(FUZZY_LIBS) $(TLSH_LIBS) -lpthread

# avd.c is plain C, built with $(CC) - only tlsh_shim.cpp needs a C++
# compiler (see tlsh_shim.h for why). The final link above uses $(CXX)
# rather than $(CC) because it's linking in a C++ object either way
# (tlsh_shim.o) - g++ auto-links libstdc++, which plain gcc does not,
# so linking mixed C/C++ objects with $(CC) would need an explicit
# -lstdc++ instead; using $(CXX) for the link step is the more
# conventional way to handle this rather than fighting gcc for it.
avd.o: avd.c ../../av/netlink_proto.h tlsh_shim.h
	$(CC) $(CFLAGS) $(LIBNL_CFLAGS) $(YARA_CFLAGS) -c avd.c -o avd.o

tlsh_shim.o: tlsh_shim.cpp tlsh_shim.h
	$(CXX) $(CXXFLAGS) $(TLSH_CFLAGS) -c tlsh_shim.cpp -o tlsh_shim.o

clean:
	rm -f avd avd.o tlsh_shim.o

# Installs the binary, the systemd unit, and a default rules/corpus
# location under SYSCONFDIR - NOT enabled or started automatically
# (that's a deliberate, separate step: starting a daemon that scans
# and quarantines files system-wide shouldn't be a silent side effect
# of `make install`). packaging/avd.service is a template (@BINDIR@/
# @SYSCONFDIR@ placeholders) rendered here against PREFIX/SYSCONFDIR -
# DESTDIR is deliberately NOT part of the substitution: it's only a
# staging root for this install invocation (e.g. packaging into
# /tmp/pkgroot before building a distro package), not part of where
# avd actually runs once installed, so it must never end up baked
# into ExecStart.
install: avd
	install -D -m 0755 avd "$(DESTDIR)$(PREFIX)/bin/avd"
	mkdir -p "$(DESTDIR)$(UNITDIR)"
	sed -e 's|@BINDIR@|$(PREFIX)/bin|g' \
		-e 's|@SYSCONFDIR@|$(SYSCONFDIR)|g' \
		../../packaging/avd.service > "$(DESTDIR)$(UNITDIR)/avd.service"
	chmod 0644 "$(DESTDIR)$(UNITDIR)/avd.service"
	mkdir -p "$(DESTDIR)$(SYSCONFDIR)/rules"
	install -m 0644 ../../rules/*.yar "$(DESTDIR)$(SYSCONFDIR)/rules/"
	install -m 0644 ../../corpus/fuzzy_hashes.txt \
		"$(DESTDIR)$(SYSCONFDIR)/fuzzy_hashes.txt"
	install -m 0644 ../../corpus/tlsh_hashes.txt \
		"$(DESTDIR)$(SYSCONFDIR)/tlsh_hashes.txt"
	@echo
	@echo "Installed:"
	@echo "  $(DESTDIR)$(PREFIX)/bin/avd"
	@echo "  $(DESTDIR)$(UNITDIR)/avd.service"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/rules/*.yar"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/fuzzy_hashes.txt"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/tlsh_hashes.txt"
	@echo
	@echo "Not started - review the unit, then:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now avd.service"

.PHONY: clean install
