/*
 * tlsh_shim.h - plain-C interface to libtlsh, whose only public API is
 * a C++ class (Tlsh, in <tlsh.h> - installed flat on Debian/Ubuntu,
 * under a tlsh/ subdirectory on Arch/CachyOS, see tlsh_shim.cpp's own
 * comment) with no extern "C" surface at all - confirmed against the
 * actual upstream header, not assumed. avd.c is plain C, so it can't
 * call libtlsh directly; this shim is the thin C++ translation unit
 * (tlsh_shim.cpp) that bridges the two, compiled with the C++
 * compiler and linked into the otherwise-C avd binary. See the
 * Makefile's TLSH_LIBS/TLSH_CFLAGS checks for how the build detects
 * libtlsh and its header location, and falls back to gcc-only if
 * it's absent.
 *
 * This is a genuinely different integration shape than ssdeep's
 * (fuzzy.h is a plain C header, libfuzzy links directly into avd.c
 * with no wrapper needed) - not a design inconsistency, a consequence
 * of libtlsh upstream never having shipped a C API at all, on any
 * distro's packaging.
 */
#ifndef AV_TLSH_SHIM_H
#define AV_TLSH_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns the SAFE MAXIMUM length (in hex chars, NOT including the
 * NUL terminator) that av_tlsh_hash_fd() will ever write - deliberately
 * generous, not tied to any one build/bucket configuration's exact
 * output length (see AV_TLSH_HASH_BUFLEN's comment in tlsh_shim.cpp
 * for why: upstream TLSH's actual hash length varies by libtlsh's own
 * compile-time bucket/checksum configuration, which this project
 * doesn't control or know at avd.c's compile time either way).
 * Callers should size their buffer to at least this + 1. */
size_t av_tlsh_hash_maxlen(void);

/* Hashes the already-open file `fd`, seeking to its start first (same
 * end result as fuzzy_hash_file()'s own internal seek-to-start
 * behavior, which check_fuzzy_corpus() in avd.c already relies on -
 * callers should pass a dup()'d fd, same convention as that function,
 * so this never disturbs the original fd's position) and writes the
 * hex-encoded hash into `out` (NUL-terminated).
 *
 * Returns 0 on success, -1 on a read/I/O error, -2 if the file didn't
 * contain enough data for TLSH to produce a valid hash (libtlsh's own
 * MIN_DATA_LENGTH cutoff - roughly 50-256 bytes depending on libtlsh
 * version, see tlsh_shim.cpp's version-skew comment; short files,
 * like short ssdeep inputs, just don't fuzzy-hash meaningfully at
 * all, this isn't a bug to work around - callers should treat -2 as
 * "no verdict from this algorithm", not as an error condition worth
 * logging), -3 if the hash didn't fit in `outlen` bytes (should not
 * happen if the caller sized its buffer via av_tlsh_hash_maxlen(),
 * but rejected outright rather than silently truncated either way -
 * a truncated hash would still parse as a well-formed-looking but
 * WRONG hash downstream, a worse failure mode than an honest error
 * here). */
int av_tlsh_hash_fd(int fd, char *out, size_t outlen);

/* Compares two hex-encoded TLSH hashes and returns libtlsh's own
 * totalDiff() distance: 0 = identical, larger = more different. This
 * is the OPPOSITE convention from ssdeep's fuzzy_compare() (0-100
 * similarity, higher = more similar) - callers must not mix up "score
 * >= threshold means match" (ssdeep) with "diff <= threshold means
 * match" (TLSH). Returns -1 if either hash string fails to parse. */
int av_tlsh_diff(const char *hash_a, const char *hash_b);

#ifdef __cplusplus
}
#endif

#endif /* AV_TLSH_SHIM_H */
