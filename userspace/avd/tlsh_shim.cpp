/*
 * tlsh_shim.cpp - the only translation unit in this project that
 * includes <tlsh.h> directly. See tlsh_shim.h for why this exists at
 * all (libtlsh has no C API). Kept deliberately tiny: this is a
 * bridge, not a place for any actual scanning logic - that all still
 * lives in avd.c, same as the ssdeep integration.
 *
 * Plain <tlsh.h>, not <tlsh/tlsh.h>: confirmed the hard way (a CI
 * failure, not assumed) that the header install path genuinely
 * differs by distro - Arch/CachyOS's `tlsh` package puts it at
 * /usr/include/tlsh/tlsh.h, but Debian/Ubuntu's libtlsh-dev puts it
 * flat at /usr/include/tlsh.h, no subdirectory. Using the flat name
 * here and adding -I/usr/include/tlsh in the Makefile (a no-op -I on
 * Debian/Ubuntu, where that directory doesn't exist) is what makes
 * this one #include line correct on both, rather than needing
 * #ifdef/__has_include distro-detection logic.
 *
 * VERSION SKEW, also confirmed the hard way (a second CI failure,
 * different error): Ubuntu noble's libtlsh-dev ships TLSH 3.4.4
 * (2015); Arch/CachyOS's ships 4.12.0 (current). That's a decade of
 * API drift on the one library this project can't fully control the
 * version of. Concretely: Tlsh::isValid() and the copy constructor
 * don't exist in 3.4.4 at all, and MIN_DATA_LENGTH differs (256 in
 * 3.4.4 vs ~50 in 4.12.0 non-conservative mode) - so a file between
 * roughly 50 and 256 bytes hashes successfully on Arch but not on
 * Ubuntu, a real behavioral difference this project doesn't try to
 * paper over. What both versions DO agree on, verified empirically
 * against real .deb/.pkg.tar.zst packages for each rather than
 * assumed from either header alone: getHash() itself returns a
 * non-NULL but EMPTY string when the hash never became valid (too
 * short/insufficiently diverse input), on both 3.4.4 and 4.12.0
 * alike. That's the one check below - no isValid() call, so no
 * version-specific code path is needed to support both. */
#include "tlsh_shim.h"

#include <tlsh.h>

#include <cstring>
#include <unistd.h>

/* TLSH_STRING_LEN(_REQ)/TLSH_STRING_BUFFER_LEN in <tlsh.h> are only
 * defined when BUCKETS_256/BUCKETS_128/BUCKETS_48 is set at compile
 * time (a CMake-level build option of libtlsh itself, not something a
 * consumer defines) - since this project doesn't rebuild libtlsh from
 * source, those macros are never defined here, and Tlsh's own PIMPL
 * layout (a single opaque pointer member) doesn't depend on them for
 * ABI compatibility either way. 128 comfortably covers every observed
 * getHash() output (measured 70 hex chars against both the Arch and
 * Ubuntu packages actually used in development) with headroom for
 * other bucket configurations, without depending on an unavailable
 * macro. */
#define AV_TLSH_HASH_BUFLEN 128

size_t av_tlsh_hash_maxlen(void) {
  return AV_TLSH_HASH_BUFLEN - 1;
}

int av_tlsh_hash_fd(int fd, char *out, size_t outlen) {
  Tlsh t;
  unsigned char buf[65536];
  ssize_t n;
  bool any_data = false;

  if (lseek(fd, 0, SEEK_SET) < 0)
    return -1;

  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    t.update(buf, (unsigned int)n);
    any_data = true;
  }
  if (n < 0)
    return -1;
  if (!any_data)
    return -2;

  t.final();

  /* No isValid() call - see this file's header comment on why an
   * empty (not NULL) getHash() result is the portable signal for
   * "never became valid" across both API versions this project
   * builds against. */
  const char *hash = t.getHash();
  if (!hash || !hash[0])
    return -2;

  strncpy(out, hash, outlen - 1);
  out[outlen - 1] = '\0';
  return 0;
}

int av_tlsh_diff(const char *hash_a, const char *hash_b) {
  Tlsh a, b;

  if (a.fromTlshStr(hash_a) != 0)
    return -1;
  if (b.fromTlshStr(hash_b) != 0)
    return -1;

  return a.totalDiff(&b, true);
}
