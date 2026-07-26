/*
 * behavior.h - v0.8.0: behavioral heuristics.
 *
 * Three signals, all deferred to a workqueue (never the atomic kprobe
 * path - see main.c's architecture note, this is the same lesson from
 * v0.1.0 applied again):
 *   1. Rapid write-intent file opens in a short window (ransomware-like:
 *      touching many files fast)
 *   2. Write-intent opens or deletions targeting sensitive paths
 *      (/etc/passwd, /etc/shadow, ~/.ssh, /boot)
 *   3. A process deleting the very executable it was started from
 *      (self-deleting binary - dropper/backdoor behavior)
 *
 * All per-PID state lives in a single mutex-protected hashtable, since
 * (unlike sigtable.c, which is read/written from arbitrary process
 * contexts) every access here now happens from workqueue context only
 * - the atomic kprobe handlers in main.c do nothing but copy a path
 * string and schedule work.
 */

#ifndef AV_BEHAVIOR_H
#define AV_BEHAVIOR_H

#include <linux/types.h>
#include <linux/pid.h>

int av_behavior_init(void);
void av_behavior_exit(void);

/* Called after a process's execve has been checked clean (signature +
 * YARA/daemon), so later unlink checks can tell if it's deleting its
 * own binary. */
void av_behavior_record_exec(pid_t pid, const char *path);

/* Called from the openat work handler. If the open is write-intent
 * (flags indicate O_WRONLY/O_RDWR/O_CREAT/O_TRUNC) this updates the
 * sliding-window counter and checks the sensitive-path list, killing
 * target_pid and logging if either heuristic trips. Safe to call for
 * every openat regardless of flags - it's a no-op for read-only opens. */
void av_behavior_check_openat(pid_t pid, const char *path, int flags,
                               struct pid *target_pid);

/* Called from the unlink/unlinkat work handler. Checks self-delete
 * (path matches this pid's recorded exec path) and the sensitive-path
 * list, killing target_pid and logging on either match. */
void av_behavior_check_unlink(pid_t pid, const char *path,
                               struct pid *target_pid);

#endif /* AV_BEHAVIOR_H */
