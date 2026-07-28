/*
 * behavior.c - v0.8.0: behavioral heuristics implementation.
 * See behavior.h for the design summary.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/stringhash.h>

#include "behavior.h"

#define BEHAVIOR_BITS 10 /* 1024 buckets */
#define WRITE_OPEN_WINDOW_MS  2000 /* sliding window size */
#define WRITE_OPEN_THRESHOLD  50   /* DISTINCT write-intent opens within
                                    * the window that trip the "rapid
                                    * modification" heuristic - tunable,
                                    * not derived from any real
                                    * ransomware sample; raised from an
                                    * initial 20 after real VM testing
                                    * showed systemd's routine cgroup
                                    * writes tripping it well within
                                    * normal boot activity - see README
                                    * for the incident writeup */
#define MAX_TRACKED_PATHS WRITE_OPEN_THRESHOLD
                                   /* Sized to exactly cover the
                                    * threshold: a real mass-distinct-
                                    * file writer will trip `rapid`
                                    * from the dedup set alone by the
                                    * time it's full, so there's no
                                    * window where the ring buffer
                                    * overflowing could hide a genuine
                                    * positive. See the note on
                                    * recent_path_hashes below for why
                                    * distinct-path counting exists at
                                    * all. */

/* Paths under these prefixes are excluded from BOTH the rapid-write
 * counter and the sensitive-path check entirely - not just given a
 * pass on one heuristic. These are pseudo-filesystems (sysfs, procfs)
 * and device nodes, not user data: systemd alone writes to dozens of
 * cgroup control files under /sys/fs/cgroup/ as completely routine
 * service management, and terminal I/O under /dev/tty* triggered a
 * false positive in real testing. Ransomware-style "rapid file
 * modification" is meaningful for user data (documents, /home,
 * mounted volumes) - it is not meaningful for kernel control-plane
 * interfaces, and treating them the same caused this heuristic to
 * try to kill PID 1 during ordinary system operation. */
static const char * const excluded_path_prefixes[] = {
    "/sys/",
    "/proc/",
    "/dev/",
};
#define NUM_EXCLUDED_PREFIXES ARRAY_SIZE(excluded_path_prefixes)

static bool path_is_excluded(const char *path)
{
    size_t i;

    for (i = 0; i < NUM_EXCLUDED_PREFIXES; i++) {
        size_t len = strlen(excluded_path_prefixes[i]);

        if (!strncmp(path, excluded_path_prefixes[i], len))
            return true;
    }
    return false;
}

/* Substring match against these flags the corresponding heuristic.
 * Deliberately simple (no regex/glob) to keep this fully atomic-safe
 * if ever needed in a tighter path later, and easy to reason about. */
static const char * const sensitive_path_substrings[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/boot/",
    "/.ssh/",
};
#define NUM_SENSITIVE_SUBSTRINGS ARRAY_SIZE(sensitive_path_substrings)

struct av_behavior_entry {
    struct hlist_node node;
    pid_t pid; /* tgid (process ID), not a thread id - see behavior.h */
    char exec_path[PATH_MAX];    /* recorded at execve time, empty if unknown */
    unsigned int write_open_count;
    unsigned long window_start_jiffies;

    /* Dedup ring buffer for the rapid-write-open heuristic - counts
     * DISTINCT paths written in the window, not raw open() calls.
     * Without this, a process rewriting a handful of its own files
     * repeatedly (browser IndexedDB/storage metadata, sqlite WAL
     * files, log rotation) trips the same counter as one touching 50
     * separate user documents - a real false positive seen in testing
     * (Firefox/Zen's storage engine rewriting its own
     * ".metadata-v2" file). Real mass-encryption ransomware still
     * trips this because it touches many DISTINCT files; an app
     * hammering its own small file set no longer does. Hashes only
     * (not full paths) to keep this cheap and fixed-size - a 32-bit
     * hash collision could theoretically under-count two different
     * paths as one, which only makes the heuristic slightly less
     * sensitive, never more trigger-happy. */
    u32 recent_path_hashes[MAX_TRACKED_PATHS];
    unsigned int recent_path_next;   /* ring buffer write cursor */
    unsigned int recent_path_filled; /* valid entries, caps at MAX_TRACKED_PATHS */
};

static DEFINE_HASHTABLE(behavior_table, BEHAVIOR_BITS);
static DEFINE_MUTEX(behavior_lock);

static u32 pid_key(pid_t pid)
{
    return hash_32((u32)pid, BEHAVIOR_BITS);
}

/* Finds or creates the entry for `pid`. Always called under
 * behavior_lock. Returns NULL only on allocation failure. */
static struct av_behavior_entry *get_or_create_entry(pid_t pid)
{
    /* Initialized to NULL only to satisfy static analyzers that can't
     * expand hash_for_each_possible() (a nested kernel macro requiring
     * full kernel headers to resolve) - the macro itself always
     * assigns e via hlist_entry_safe() before the loop body runs, so
     * this has no effect on actual behavior, just quiets a known false
     * positive category for Linux kernel list-iteration macros. */
    struct av_behavior_entry *e = NULL;

    hash_for_each_possible(behavior_table, e, node, pid_key(pid)) {
        if (e->pid == pid)
            return e;
    }

    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return NULL;

    e->pid = pid;
    hash_add(behavior_table, &e->node, pid_key(pid));
    return e;
}

static bool path_is_sensitive(const char *path)
{
    size_t i;

    for (i = 0; i < NUM_SENSITIVE_SUBSTRINGS; i++) {
        if (strstr(path, sensitive_path_substrings[i]))
            return true;
    }
    return false;
}

/* Shared kill-and-log helper - same pid_task/rcu_read_lock/send_sig
 * pattern used in main.c's execve path, duplicated here rather than
 * shared across modules to keep behavior.c self-contained.
 *
 * SAFETY NET: never target PID 1, full stop, regardless of what
 * triggered detection. Killing init can panic the kernel outright.
 * This was NOT a hypothetical risk - an earlier version of this
 * heuristic actually tried to kill PID 1 on real hardware/VM testing
 * (systemd's routine cgroup writes tripped the rapid-write threshold).
 * The real fix is not over-triggering in the first place (see the
 * path exclusions below), but this guard stays regardless - defense
 * in depth for a security tool that can SIGKILL things is worth the
 * one branch.
 *
 * v1.0.0-merge: structured key=value log format, matching main.c's
 * av_kill - see its comment for why. */
static void kill_with_reason(struct pid *target_pid, const char *path,
                              const char *reason)
{
    struct task_struct *task;

    if (pid_nr(target_pid) == 1) {
        pr_alert("kernel-av: event=suppressed action=none type=behavioral "
                 "path=\"%s\" reason=\"%s\" pid=1\n", path, reason);
        return;
    }

    rcu_read_lock();
    task = pid_task(target_pid, PIDTYPE_PID);
    if (task) {
        pr_alert("kernel-av: event=detected action=kill type=behavioral "
                 "path=\"%s\" reason=\"%s\" pid=%d\n",
                 path, reason, pid_nr(target_pid));
        send_sig(SIGKILL, task, 0);
    }
    rcu_read_unlock();
}

void av_behavior_record_exec(pid_t pid, const char *path)
{
    struct av_behavior_entry *e;

    mutex_lock(&behavior_lock);
    e = get_or_create_entry(pid);
    if (e)
        strscpy(e->exec_path, path, sizeof(e->exec_path));
    mutex_unlock(&behavior_lock);
}

void av_behavior_check_openat(pid_t pid, const char *path, int flags,
                               struct pid *target_pid)
{
    struct av_behavior_entry *e;
    bool sensitive;
    bool rapid = false;

    /* Read-only opens aren't interesting for either heuristic here. */
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return;

    /* Pseudo-filesystem/device paths never count toward either
     * heuristic - see the comment on excluded_path_prefixes for why. */
    if (path_is_excluded(path))
        return;

    sensitive = path_is_sensitive(path);

    mutex_lock(&behavior_lock);
    e = get_or_create_entry(pid);
    if (e) {
        unsigned long window_ms = jiffies_to_msecs(
            jiffies - e->window_start_jiffies);
        bool new_window = (e->window_start_jiffies == 0 ||
                            window_ms > WRITE_OPEN_WINDOW_MS);
        u32 path_hash = full_name_hash(NULL, path, strlen(path));
        bool seen_before = false;
        unsigned int i;

        if (new_window) {
            /* Start (or restart) the window - also resets the dedup
             * set, since "distinct paths written" only means anything
             * within a single window. */
            e->window_start_jiffies = jiffies;
            e->write_open_count = 0;
            e->recent_path_next = 0;
            e->recent_path_filled = 0;
        }

        for (i = 0; i < e->recent_path_filled; i++) {
            if (e->recent_path_hashes[i] == path_hash) {
                seen_before = true;
                break;
            }
        }

        /* Only count (and only check the threshold on) a path we
         * haven't already seen in this window - repeatedly rewriting
         * the same file no longer inflates the counter. */
        if (!seen_before) {
            e->recent_path_hashes[e->recent_path_next] = path_hash;
            e->recent_path_next = (e->recent_path_next + 1) % MAX_TRACKED_PATHS;
            if (e->recent_path_filled < MAX_TRACKED_PATHS)
                e->recent_path_filled++;

            e->write_open_count++;
            if (e->write_open_count > WRITE_OPEN_THRESHOLD)
                rapid = true;
        }
    }
    mutex_unlock(&behavior_lock);

    if (sensitive)
        kill_with_reason(target_pid, path, "write-intent open of sensitive path");
    else if (rapid)
        kill_with_reason(target_pid, path,
                          "rapid file modification (possible ransomware pattern)");
}

void av_behavior_check_unlink(pid_t pid, const char *path,
                               struct pid *target_pid)
{
    const struct av_behavior_entry *e;
    bool self_delete = false;
    bool sensitive;

    if (path_is_excluded(path))
        return;

    mutex_lock(&behavior_lock);
    e = get_or_create_entry(pid);
    if (e && e->exec_path[0] != '\0' && !strcmp(e->exec_path, path))
        self_delete = true;
    mutex_unlock(&behavior_lock);

    sensitive = path_is_sensitive(path);

    if (self_delete)
        kill_with_reason(target_pid, path,
                          "self-deleting binary (possible dropper/backdoor)");
    else if (sensitive)
        kill_with_reason(target_pid, path, "deletion of sensitive path");
}

int av_behavior_init(void)
{
    hash_init(behavior_table);
    return 0;
}

void av_behavior_exit(void)
{
    struct av_behavior_entry *e;
    struct hlist_node *tmp;
    int bkt;

    mutex_lock(&behavior_lock);
    hash_for_each_safe(behavior_table, bkt, tmp, e, node) {
        hash_del(&e->node);
        kfree(e);
    }
    mutex_unlock(&behavior_lock);
}
