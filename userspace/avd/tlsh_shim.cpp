/*
 * tlsh_shim.cpp - the only translation unit in this project that
 * includes <tlsh/tlsh.h> directly. See tlsh_shim.h for why this
 * exists at all (libtlsh has no C API). Kept deliberately tiny: this
 * is a bridge, not a place for any actual scanning logic - that all
 * still lives in avd.c, same as the ssdeep integration.
 */
#include "tlsh_shim.h"

#include <tlsh/tlsh.h>

#include <cstring>
#include <unistd.h>

/* TLSH_STRING_LEN_REQ/TLSH_STRING_BUFFER_LEN in <tlsh/tlsh.h> are only
 * defined when BUCKETS_256/BUCKETS_128/BUCKETS_48 is set at compile
 * time (a CMake-level build option of libtlsh itself, not something a
 * consumer defines) - since this project doesn't rebuild libtlsh from
 * source, those macros are never defined here, and Tlsh's own PIMPL
 * layout (a single opaque pointer member) doesn't depend on them for
 * ABI compatibility either way. 128 comfortably covers every observed
 * getHash() output (measured 70-72 hex chars against the distro
 * package actually used in development) with headroom for other
 * bucket configurations, without depending on an unavailable macro. */
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
  if (!t.isValid())
    return -2;

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
