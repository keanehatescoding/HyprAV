/*
 * stage1/signature_execve - hardcoded signature list.
 *
 * Each entry is a SHA-256 hash (32 bytes / 64 hex chars) of a known-bad
 * file. This is intentionally hardcoded for stage 1 - stage 2 moves this
 * into a kernel hashtable populated at runtime from userspace.
 *
 * To add the EICAR test file's hash (see top-level README for how to
 * generate the test file):
 *   sha256sum /tmp/eicar.com
 * then paste the resulting hex digest below.
 */

#ifndef SIGNATURES_H
#define SIGNATURES_H

struct av_signature {
    const char *name;      /* human-readable label for logging */
    const char *sha256_hex; /* lowercase hex, 64 chars */
};

/* Populate with real hashes before testing. The EICAR hash below is the
 * standard, well-known hash of the official EICAR test string - safe to
 * ship in source control, it does not contain or reproduce any malware. */
static const struct av_signature known_signatures[] = {
    {
        .name = "EICAR-Test-File",
        .sha256_hex = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0",
    },
    /* Add more entries here as you build out your test corpus. */
};

#define NUM_SIGNATURES (sizeof(known_signatures) / sizeof(known_signatures[0]))

#endif /* SIGNATURES_H */
