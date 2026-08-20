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
 * ABI compatibility either way.
 *
 * 200 is deliberately generous, not just "big enough for what was
 * measured": the packages actually used in development (Arch's
 * 4.12.0, Ubuntu's 3.4.4) both produce 70 hex chars, but upstream
 * TLSH supports BUCKETS_256 configurations that can run up to 134
 * (1-byte checksum) or 138 (3-byte checksum) hex chars, plus a
 * 2-char "T1" version prefix that's the default in library >=5.0.0 -
 * up to ~140 chars in the worst documented case. This project only
 * ever builds against the default/compact config in practice, but
 * getHash() truncating silently into a too-small buffer would corrupt
 * the hash into something fromTlshStr() then rejects, which
 * check_tlsh_corpus() in avd.c would in turn treat as "never matches
 * anything" - a silent false-negative on every scan, not a crash, the
 * worst kind of bug for a security tool to have. av_tlsh_hash_fd()
 * below still refuses to write into an undersized buffer rather than
 * trusting this constant alone - defense in depth, not either/or. */
#define AV_TLSH_HASH_BUFLEN 200

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

  /* Reject rather than silently truncate if the hash somehow doesn't
   * fit - see AV_TLSH_HASH_BUFLEN's comment above on why a corrupted-
   * but-"successful" hash is a worse failure mode than an honest
   * error here (a truncated hash still round-trips through
   * fromTlshStr() far enough to look plausible, then just quietly
   * never matches anything). */
  if (strlen(hash) >= outlen)
    return -3;

  strcpy(out, hash);
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
