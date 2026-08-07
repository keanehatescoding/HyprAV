/*
 * behavior.h - v0.8.0: behavioral heuristics.
 *
 * Four signals, all deferred to a workqueue (never the atomic kprobe
 * path - see main.c's architecture note, this is the same lesson from
 * v0.1.0 applied again):
 *   1. Rapid write-intent file opens in a short window (ransomware-like:
 *      touching many files fast)
 *   2. Write-intent opens or deletions targeting sensitive paths
 *      (/etc/passwd, /etc/shadow, ~/.ssh, /boot)
 *   3. A process deleting the very executable it was started from
 *      (self-deleting binary - dropper/backdoor behavior)
 *   4. Rapid extension-append renames in a short window (ransomware's
 *      actual encryption-pass signature: document.docx ->
 *      document.docx.crypt), plus renames touching a sensitive path
 *      on either end - see av_behavior_check_rename() below
 *
 * All per-PROCESS state lives in a single mutex-protected hashtable,
 * since (unlike sigtable.c, which is read/written from arbitrary
 * process contexts) every access here now happens from workqueue
 * context only - the atomic kprobe handlers in main.c do nothing but
 * copy a path string and schedule work.
 *
 * IMPORTANT: every `pid_t pid` below is a tgid (thread-group/process
 * ID, i.e. what `ps` calls PID), NOT the individual calling thread's
 * id. main.c captures it via task_tgid_nr(current), not current->pid.
 * Keying by the per-thread id would let a multi-threaded process
 * evade the rapid-write-open heuristic by spreading writes across
 * threads, each with its own independent counter - this was fixed
 * after review; keep new call sites consistent with tgid.
 *
 * v1.0.0-cont: trusted-process exemption for the rapid-write heuristic
 * specifically (signature/YARA/fuzzy checks still fully apply to
 * trusted processes - this ONLY exempts the write-count heuristic).
 * Added after this exact heuristic produced FOUR separate real false
 * positives against browsers (systemd cgroup writes, browser cache
 * repeat-writes, browser cache/journal churn, per-origin storage
 * metadata files) - each fix so far excluded a specific PATH PATTERN,
 * and each fix was followed by a new pattern the previous one didn't
 * cover. Path-pattern exclusion is whack-a-mole against an application
 * that will keep inventing new file-naming conventions; exempting the
 * PROCESS (by binary hash, not path - path is spoofable, hash isn't)
 * is the standard real-world EDR answer to "this legitimate app is
 * just inherently write-heavy in ways no path pattern fully captures".
 * See av_behavior_trust_add() below and docs on WHY this doesn't
 * weaken detection against actually-unknown processes: it only ever
 * suppresses the volume-based signal for binaries whose IDENTITY
 * (exact SHA-256) has been explicitly vouched for - malware can't
 * "become trusted" by mimicking a path or file name.
 */

#ifndef AV_BEHAVIOR_H
#define AV_BEHAVIOR_H

#include <linux/types.h>
#include <linux/pid.h>

int av_behavior_init(void);
void av_behavior_exit(void);

/* Called after a process's execve has been checked clean (signature +
 * YARA/daemon), so later unlink checks can tell if it's deleting its
 * own binary, and so the rapid-write heuristic can tell if this
 * process's binary is on the trusted list. `pid` is the tgid - see
 * the note above. `sha256_hex` is the already-computed digest from
 * hash_file_multi() in main.c - reused, not recomputed. */
void av_behavior_record_exec(pid_t pid, const char *path,
                              const char *sha256_hex);

/* Called from the openat work handler. If the open is write-intent
 * (flags indicate O_WRONLY/O_RDWR/O_CREAT/O_TRUNC) this updates the
 * sliding-window counter and checks the sensitive-path list, killing
 * target_pid and logging if either heuristic trips - UNLESS this
 * process's binary hash is on the trusted list, in which case the
 * rapid-write counter is skipped entirely (the sensitive-path check
 * still applies regardless of trust). Safe to call for every openat
 * regardless of flags - it's a no-op for read-only opens. `pid` is
 * the tgid - see the note above. */
void av_behavior_check_openat(pid_t pid, const char *path, int flags,
                               struct pid *target_pid);

/* Called from the unlink/unlinkat work handler. Checks self-delete
 * (path matches this pid's recorded exec path) and the sensitive-path
 * list, killing target_pid and logging on either match. Trust status
 * does NOT exempt this check - deleting your own binary or a sensitive
 * path is worth flagging regardless of how trusted the process is.
 * `pid` is the tgid - see the note above. */
void av_behavior_check_unlink(pid_t pid, const char *path,
                               struct pid *target_pid);

/* Called from the rename/renameat/renameat2 work handler. Flags a
 * burst of "extension-append" renames (oldpath's basename with a
 * non-empty ".something" suffix tacked on - e.g. document.docx ->
 * document.docx.crypt) within a short window against DISTINCT source
 * files: the observable shape of ransomware's encryption pass,
 * regardless of which specific extension a given family happens to
 * use, rather than a brittle hardcoded extension blocklist. Also
 * flags a rename involving a sensitive path on either end. Same
 * trust exemption as av_behavior_check_openat: trust skips the
 * volume-based signal only, never the sensitive-path check. `pid` is
 * the tgid - see the note above. */
void av_behavior_check_rename(pid_t pid, const char *oldpath,
                               const char *newpath, struct pid *target_pid);

/* Trusted-binary-hash management, mirroring sigtable.c's pattern.
 * Returns 0 on success, negative errno on failure (-EINVAL for a
 * malformed hex string, -ENOMEM on allocation failure). */
int av_behavior_trust_add(const char *sha256_hex, const char *name);
int av_behavior_trust_del(const char *sha256_hex);

/* Creates/removes /proc/kernel_av_trusted for runtime management
 * (add/del/list), same usage pattern as sigtable.c's
 * /proc/kernel_av_signatures. Call after av_behavior_init() / before
 * av_behavior_exit(). */
int av_behavior_trust_proc_init(void);
void av_behavior_trust_proc_exit(void);

#endif /* AV_BEHAVIOR_H */
