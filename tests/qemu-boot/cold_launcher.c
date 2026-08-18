/* Dedicated regression case for the documented gap in av/main.c's
 * handler_pre()/handler_pre_execveat() (see that comment, and
 * README.md's CI section): strncpy_from_user() in atomic/kprobe
 * context can't sleep to fault in a userspace page that isn't
 * resident yet, so a pathname argument on a genuinely cold page makes
 * the hook silently skip hashing/killing.
 *
 * This is a SEPARATE, minimal binary rather than another code path in
 * init.c on purpose: the only reliable way to guarantee a pathname
 * argument's backing page is genuinely untouched by *this process* is
 * for it to be the very first thing a freshly execve()'d image
 * references, before anything else in the program has had a chance
 * to touch nearby .rodata. init.c itself can't offer that guarantee
 * once it's already running (mounting filesystems, reading av.ko,
 * printing status, etc. all touch various pages first) - but a tiny
 * program whose entire body is "execve() a literal path, do nothing
 * else first" gets a fresh, untouched address space from the kernel's
 * own ELF loader and immediately exec's before doing anything that
 * would fault this string in as a side effect.
 *
 * Deliberately does NOT touch the pathname first (that's init.c's
 * main test's job, demonstrating detection working for the common
 * case) - the entire point here is reproducing the cold-page bypass
 * on purpose, not avoiding it.
 */
#include <unistd.h>

int main(void) {
  char *const argv[] = {"/tmp/eicar_cold.com", NULL};

  execve("/tmp/eicar_cold.com", argv, NULL);
  return 1; /* only reached if execve itself failed */
}
