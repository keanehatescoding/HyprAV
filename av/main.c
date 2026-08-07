/*
 * main.c - av module entry point: kprobe on execve, workqueue-deferred
 * multi-algorithm hashing (MD5/SHA-1/SHA-256), lookup against the
 * runtime-managed signature table (sigtable.c), kill on match.
 *
 * ARCHITECTURE NOTE: kprobe pre-handlers run in an ATOMIC context - no
 * sleeping, no file I/O, no GFP_KERNEL. handler_pre() only copies the
 * exec path (GFP_ATOMIC) and schedules a work item; all file I/O,
 * hashing, and signature lookups happen in av_work_fn(), which runs in
 * a normal sleepable process context via a dedicated workqueue. See the
 * v0.1.0 changelog for the incident that made this non-negotiable: an
 * earlier version did the hashing directly in the kprobe handler and
 * corrupted kernel state on every execve.
 *
 * v0.2.0 changes from v0.1.0:
 *   - signatures are no longer hardcoded - they live in a kernel
 *     hashtable (sigtable.c), managed at runtime via
 *     /proc/kernel_av_signatures
 *   - hashes are computed for MD5, SHA-1, and SHA-256 in a single file
 *     read pass; a match on any one algorithm triggers a kill
 *
 * v0.3.0-prep changes:
 *   - added a Generic Netlink channel (netlink_chan.c) to a userspace
 *     daemon (avd). On a signature miss, the daemon gets a second look
 *     (stubbed as always-clean until the real YARA/heuristic logic
 *     lands in avd - see docs/netlink-protocol.md and
 *     userspace/avd/avd.c). Fail-open if no daemon is connected or it
 *     doesn't respond within DAEMON_TIMEOUT_MS.
 *
 * v0.8.0 changes: behavioral heuristics (behavior.c), back on the
 * kernel side after several userspace-only milestones. Three new
 * kprobe hooks - openat, unlink, unlinkat - follow the SAME atomic-
 * context discipline as the execve hook: pre-handlers only copy a
 * path string (GFP_ATOMIC) and schedule work; all logic (sensitive-
 * path matching, sliding-window counting, self-delete comparison,
 * the actual kill) happens in behavior.c, called from workqueue
 * context. Deliberately hooks openat (path directly available as a
 * user pointer) rather than write() (only gives an fd - resolving
 * that to a path from a DIFFERENT process's file table inside a
 * workqueue is a genuinely risky, version-fragile kernel API area
 * that this design avoids entirely).
 *
 * Later addition: rename/renameat/renameat2 hooks, closing a
 * previously-documented gap - ransomware's actual encryption-pass
 * signature is renaming files to add an extension (document.docx ->
 * document.docx.crypt), which none of the hooks above observed. Same
 * atomic-context discipline again: pre-handlers copy TWO path strings
 * and schedule work; av_behavior_check_rename() in behavior.c does
 * the actual extension-append-shape detection, sliding-window
 * counting, and sensitive-path check. See behavior.h/behavior.c and
 * README.md for the detection design.
 *
 * Build:   make
 * Load:    sudo insmod av.ko
 * Seed:    a default EICAR SHA-256 signature is added at module load
 *          (see av_init) so testing works out of the box; add more via
 *          /proc/kernel_av_signatures or the avctl CLI
 *          (userspace/avctl/).
 * Check:   dmesg | tail -20
 * Unload:  sudo rmmod av
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/fcntl.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/sched/signal.h>
#include <linux/workqueue.h>
#include <linux/pid.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/kdev_t.h>

#include "sigtable.h"
#include "netlink_proto.h"
#include "netlink_chan.h"
#include "behavior.h"

#define HOOKED_SYSCALL_NAME "__x64_sys_execve" /* see README re: arch */
#define READ_CHUNK_SIZE     4096
#define MAX_HASH_FILE_SIZE  (256 * 1024 * 1024) /* 256 MB cap on what
                                   * hash_file_multi() will read - without
                                   * it, execve of a multi-GB binary hashes
                                   * the whole thing inline in the worker,
                                   * and execve of a FIFO/device (which
                                   * fails in the exec syscall itself, but
                                   * still reaches record_exec's queued
                                   * work) blocks kernel_read() forever on
                                   * a FIFO with no writer. Neither is
                                   * fatal on its own, but both tie up a
                                   * workqueue thread indefinitely; see
                                   * the S_ISREG/i_size checks below. */
#define DAEMON_TIMEOUT_MS   12000 /* fail-open if the daemon doesn't answer
                                   * in time - see docs/netlink-protocol.md
                                   * for the fail-open vs fail-closed
                                   * discussion.
                                   *
                                   * Was 2000: avd's own SCAN_TIMEOUT_SECS
                                   * (avd.c) is 10s, so any scan taking
                                   * longer than 2s had its verdict
                                   * dropped as an "unknown/expired reqid"
                                   * here regardless of what avd decided -
                                   * the exec got killed by THIS timeout's
                                   * fail-open path, and avd's 10s budget
                                   * was effectively dead code. 12000ms
                                   * gives a couple seconds of headroom
                                   * over avd's real worst case rather
                                   * than matching it exactly, so a scan
                                   * that legitimately takes close to 10s
                                   * still gets to deliver its verdict
                                   * instead of racing this timeout. */

static struct kprobe kp_execve = {
    .symbol_name = HOOKED_SYSCALL_NAME,
};
static struct kprobe kp_openat = {
    .symbol_name = "__x64_sys_openat",
};
static struct kprobe kp_unlink = {
    .symbol_name = "__x64_sys_unlink",
};
static struct kprobe kp_unlinkat = {
    .symbol_name = "__x64_sys_unlinkat",
};
static struct kprobe kp_rename = {
    .symbol_name = "__x64_sys_rename",
};
static struct kprobe kp_renameat = {
    .symbol_name = "__x64_sys_renameat",
};
static struct kprobe kp_renameat2 = {
    .symbol_name = "__x64_sys_renameat2",
};

static struct workqueue_struct *av_wq;

/* Resolves a syscall's `dfd` argument into a struct path suitable as
 * the base for a later relative-path lookup, mirroring the get_fs_pwd()
 * capture execve's handler_pre() already did. Callable from ATOMIC
 * (kprobe) context: AT_FDCWD is by far the common case (plain
 * openat/unlink/rename with no real base fd) and just reuses the same
 * cwd capture; a real fd only needs fget_raw() to look up the
 * descriptor table entry and bump its refcount - no I/O, no sleeping,
 * same atomic-safety class as get_fs_pwd(). Uses fget_raw()/fput()
 * rather than the newer fdget_raw()/fdput() struct-fd pair: the latter
 * isn't EXPORT_SYMBOL'd for out-of-tree modules on every kernel (it
 * modpost-failed as an undefined symbol on 7.1.6-cachyos), while
 * fget_raw() is the long-standing exported entry point for exactly
 * this "look up a file by fd, take a real reference" use case - same
 * underlying RCU/refcount lookup, just a plain struct file* instead of
 * struct fd. This is the fix for the
 * dfd-ignored evasion: openat(fd_for_/etc, "shadow", ...) previously
 * reached behavior.c as bare "shadow", which trivially bypassed every
 * sensitive-path check. `out` is populated with a path reference the
 * caller must path_put() - released in each work_fn's cleanup, same
 * lifetime discipline as av_work's existing pwd field. Returns false
 * (nothing to put) if dfd is a real fd but doesn't resolve to an open
 * file - e.g. a bogus/already-closed fd racing the syscall itself. */
static bool resolve_dfd_path(int dfd, struct path *out)
{
    if (dfd == AT_FDCWD) {
        get_fs_pwd(current->fs, out);
        return true;
    }

    {
        struct file *f = fget_raw(dfd);

        if (!f)
            return false;

        *out = f->f_path;
        path_get(out);
        fput(f);
    }

    return true;
}

/* Resolves `path` into a NUL-terminated absolute path string written
 * into `out` (capacity out_len), using `base` (captured by
 * resolve_dfd_path() above, in atomic context, back when `path` was
 * still meaningful relative to the calling process) when `path` itself
 * isn't already absolute. Must run from SLEEPABLE context - d_path()
 * can be called under most locks but the whole point here is to be
 * called from the workqueue, consistent with every other non-atomic-
 * safe operation in this file.
 *
 * Deliberately does NOT use vfs_path_lookup()/full canonicalization:
 * unlike open_exec_target() (which needs a real open fd and so must
 * fully resolve the target), rename's newpath and an O_CREAT openat
 * target may not exist yet, and unlink's target may be a symlink we
 * must NOT follow. Instead this resolves only the base directory (dfd)
 * to its absolute path via d_path() and string-concatenates the
 * (still possibly containing "." / ".." components) relative
 * remainder onto it. That's sufficient for behavior.c's prefix/
 * substring matching and exec_path self-delete comparison - the
 * literal path components a caller supplied are still present in the
 * resulting string, just not collapsed - but note it for what it is:
 * a pragmatic partial resolution, not a canonical realpath(). On any
 * failure this falls back to copying `path` through unresolved rather
 * than dropping the event - a degraded (pre-fix) check on this one
 * call is better than silently skipping it. */
static void resolve_absolute_path(const char *path, const struct path *base,
                                   char *out, size_t out_len)
{
    char *tmp;
    char *dirpath;

    if (path[0] == '/') {
        strscpy(out, path, out_len);
        return;
    }

    tmp = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!tmp) {
        strscpy(out, path, out_len);
        return;
    }

    dirpath = d_path(base, tmp, PATH_MAX);
    if (IS_ERR(dirpath))
        strscpy(out, path, out_len);
    else
        snprintf(out, out_len, "%s/%s", dirpath, path);

    kfree(tmp);
}

struct av_work {
    struct work_struct work;
    struct pid *target_pid;
    pid_t tgid; /* thread-group (process) ID - see the tgid-vs-pid note
                 * on av_openat_work below; captured here so
                 * av_behavior_record_exec() keys behavior state by
                 * process rather than by the individual thread that
                 * happened to call execve(). */
    struct path pwd; /* the exec'ing process's cwd at the moment
                       * handler_pre() ran, captured via get_fs_pwd()
                       * (atomic-safe: it's just a refcount bump under
                       * current->fs->lock, no I/O). A relative `path`
                       * below must be resolved against THIS, not
                       * against whatever the workqueue thread's own
                       * cwd happens to be by the time av_work_fn()
                       * runs - see open_exec_target(). Released with
                       * path_put() in av_work_fn()'s cleanup. */
    char path[PATH_MAX];
};

struct algo_ctx {
    const char *crypto_name;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    u8 *digest_bin;
    size_t digest_bin_len;
    char *digest_hex;   /* points into the matching field of av_digest */
};

/* Captures the identity of the file that was ACTUALLY opened and
 * hashed by hash_file_multi(), so a signature/daemon verdict can be
 * logged against something more forensically specific than a path
 * string alone. This does NOT close the TOCTOU described on
 * av_work_fn() below - it's captured well after the real exec already
 * happened, from our own (possibly-already-raced) open - it just makes
 * a post-incident "was this really the file that ran" check possible
 * from the dmesg record instead of impossible. */
struct av_file_identity {
    dev_t dev;
    unsigned long ino;
    loff_t size;
};

static void bin_to_hex(const u8 *bin, size_t bin_len, char *hex_out)
{
    size_t i;

    for (i = 0; i < bin_len; i++)
        snprintf(hex_out + i * 2, 3, "%02x", bin[i]);
    hex_out[bin_len * 2] = '\0';
}

/* Resolves and opens the exec target, honoring `path` as relative to
 * `pwd` (the calling process's cwd at exec time - see the av_work
 * comment) rather than to whatever directory this happens to run in.
 * Called from av_work_fn(), i.e. sleepable process context, so
 * vfs_path_lookup()'s potential I/O is fine here even though it would
 * not have been back in handler_pre().
 *
 * An absolute path needs no resolution against pwd at all (and pwd may
 * be garbage/unused in that case - filp_open() ignores it). This is
 * also why plain filp_open(path, ...) worked "by accident" for every
 * absolute-path exec: glibc's execvp() always resolves PATH lookups to
 * an absolute path before the actual execve() syscall, so this bug
 * only ever showed up for a program calling execve() directly with a
 * relative filename. */
static struct file *open_exec_target(const char *path, const struct path *pwd)
{
    struct file *f;

    if (path[0] == '/') {
        f = filp_open(path, O_RDONLY, 0);
    } else {
        struct path resolved;
        int err;

        err = vfs_path_lookup(pwd->dentry, pwd->mnt, path, LOOKUP_FOLLOW,
                               &resolved);
        if (err)
            return ERR_PTR(err);

        f = dentry_open(&resolved, O_RDONLY, current_cred());
        path_put(&resolved);
    }

    return f;
}

/* Computes MD5, SHA-1, and SHA-256 of the file at `path` in a single
 * read pass. MUST be called from a sleepable (process) context only.
 * `ident_out` (optional, may be NULL) is filled in with the identity
 * of the file actually opened - see struct av_file_identity above and
 * the TOCTOU note on av_work_fn(). */
static int hash_file_multi(const char *path, const struct path *pwd,
                            struct av_digest *out,
                            struct av_file_identity *ident_out)
{
    struct file *f;
    u8 md5_bin[16], sha1_bin[20], sha256_bin[32];
    struct algo_ctx ctx[3] = {
        { "md5",    NULL, NULL, md5_bin,    sizeof(md5_bin),    out->md5 },
        { "sha1",   NULL, NULL, sha1_bin,   sizeof(sha1_bin),   out->sha1 },
        { "sha256", NULL, NULL, sha256_bin, sizeof(sha256_bin), out->sha256 },
    };
    void *buf = NULL;
    loff_t pos = 0;
    ssize_t n;
    int ret = 0;
    int i;

    f = open_exec_target(path, pwd);
    if (IS_ERR(f))
        return PTR_ERR(f);

    /* Only hash regular files, and only up to MAX_HASH_FILE_SIZE - see
     * the macro comment. A FIFO/device/socket reaching here means the
     * execve() that triggered this work already failed for the caller
     * (you can't exec a FIFO), but av_work_fn() queued the work before
     * that failure was knowable, so we still have to guard against it
     * here rather than assume the caller filtered it out. */
    if (!S_ISREG(file_inode(f)->i_mode)) {
        ret = -EINVAL;
        goto out;
    }
    if (i_size_read(file_inode(f)) > MAX_HASH_FILE_SIZE) {
        ret = -EFBIG;
        goto out;
    }

    /* Identity of the file we're about to hash - captured here, right
     * after confirming it's a regular file we're actually going to
     * read, so it reflects the exact inode the digest below was
     * computed from. */
    if (ident_out) {
        struct inode *inode = file_inode(f);

        ident_out->dev = inode->i_sb->s_dev;
        ident_out->ino = inode->i_ino;
        ident_out->size = i_size_read(inode);
    }

    for (i = 0; i < 3; i++) {
        ctx[i].tfm = crypto_alloc_shash(ctx[i].crypto_name, 0, 0);
        if (IS_ERR(ctx[i].tfm)) {
            ret = PTR_ERR(ctx[i].tfm);
            ctx[i].tfm = NULL;
            goto out;
        }
        ctx[i].desc = kmalloc(sizeof(*ctx[i].desc) +
                               crypto_shash_descsize(ctx[i].tfm), GFP_KERNEL);
        if (!ctx[i].desc) {
            ret = -ENOMEM;
            goto out;
        }
        ctx[i].desc->tfm = ctx[i].tfm;
        ret = crypto_shash_init(ctx[i].desc);
        if (ret)
            goto out;
    }

    buf = kmalloc(READ_CHUNK_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    while ((n = kernel_read(f, buf, READ_CHUNK_SIZE, &pos)) > 0) {
        for (i = 0; i < 3; i++) {
            ret = crypto_shash_update(ctx[i].desc, buf, n);
            if (ret)
                goto out;
        }
    }
    if (n < 0) {
        ret = n;
        goto out;
    }

    for (i = 0; i < 3; i++) {
        ret = crypto_shash_final(ctx[i].desc, ctx[i].digest_bin);
        if (ret)
            goto out;
        bin_to_hex(ctx[i].digest_bin, ctx[i].digest_bin_len, ctx[i].digest_hex);
    }

out:
    kfree(buf);
    for (i = 0; i < 3; i++) {
        kfree(ctx[i].desc);
        if (ctx[i].tfm)
            crypto_free_shash(ctx[i].tfm);
    }
    filp_close(f, NULL);
    return ret;
}

/* Shared kill-and-log helper, mirroring behavior.c's kill_with_reason -
 * see its comment for why the PID-1 guard is unconditional and
 * non-negotiable regardless of what triggered detection.
 *
 * v1.0.0-merge: structured key=value log format (event=... type=...
 * etc.) instead of free-form sentences, so dmesg output is grep/awk-
 * parseable for any future log aggregation. Kept on one line per
 * event deliberately. */
static void av_kill(struct pid *target_pid, const char *path,
                     const char *type, const char *reason,
                     const struct av_file_identity *ident)
{
    struct task_struct *task;

    if (pid_nr(target_pid) == 1) {
        pr_alert("kernel-av: event=suppressed action=none type=%s "
                 "path=\"%s\" reason=\"%s\" pid=1\n", type, path, reason);
        return;
    }

    rcu_read_lock();
    task = pid_task(target_pid, PIDTYPE_PID);
    if (task) {
        pr_alert("kernel-av: event=detected action=kill type=%s "
                 "path=\"%s\" reason=\"%s\" pid=%d dev=%u:%u ino=%lu size=%lld\n",
                 type, path, reason, pid_nr(target_pid),
                 MAJOR(ident->dev), MINOR(ident->dev), ident->ino,
                 (long long)ident->size);
        send_sig(SIGKILL, task, 0);
    }
    rcu_read_unlock();
}

/* Runs in a kernel worker thread - safe to sleep, do file I/O, use
 * GFP_KERNEL. This is where all "heavy" work happens.
 *
 * KNOWN TOCTOU (see review item #3 / README): by the time this runs,
 * the real execve() already completed and the target process is
 * already running - the kernel resolved and mapped ITS OWN copy of
 * the executable well before this workqueue item was even scheduled.
 * hash_file_multi() below does a SEPARATE, LATER open of `aw->path`
 * (resolved against the cwd captured back in handler_pre() - see
 * av_work's pwd field) to compute a hash for the signature/daemon
 * check. Nothing guarantees these are the same inode: an attacker who
 * can win the race (replace the file, or repoint a symlink in the
 * path, between the real exec and this open) can make the signature
 * check run against a swapped-in decoy while their actual malicious
 * code is already executing, undetected. This is inherent to the
 * defer-to-workqueue design (see the ARCHITECTURE NOTE at the top of
 * this file - hashing can't happen in the atomic kprobe path) and
 * can't be closed from a kprobe on the syscall boundary; genuinely
 * closing it means moving to a hook with access to the kernel's own
 * already-resolved struct file for the exec (e.g. an LSM
 * bprm_check_security hook), which is a real redesign, not a patch.
 * Two things this file does instead, short of that redesign: (1)
 * av_file_identity below records exactly which inode was hashed, so a
 * post-incident dmesg review can at least tell whether that inode
 * still matches what's on disk; (2) O_NOFOLLOW was deliberately NOT
 * added to open_exec_target() - it would only guard the narrow case
 * where the final path component itself is a symlink, at the cost of
 * breaking hashing for every LEGITIMATELY symlinked binary (/usr/bin/
 * python and friends), while doing nothing for a same-path file
 * replacement, which is the more general form of this race. */
static void av_work_fn(struct work_struct *w)
{
    struct av_work *aw = container_of(w, struct av_work, work);
    struct av_digest digest;
    struct av_file_identity ident;
    char sig_name[AV_SIG_NAME_LEN];
    char reason[AV_SIG_NAME_LEN + 32];
    char *abs_path;
    int ret;

    /* hash_file_multi()/open_exec_target() already resolve a relative
     * aw->path against aw->pwd correctly for the purpose of opening the
     * right file. But what gets RECORDED as this process's exec_path
     * (for the unlink hook's self-delete comparison, av_behavior_check_
     * unlink()) was still the raw, possibly-relative string - so
     * `./payload` exec'd and `payload` unlinked from the same cwd never
     * matched. Resolve once here so exec_path and the (now also
     * resolved - see resolve_dfd_path()/resolve_absolute_path() above)
     * unlink path are directly comparable strings. */
    abs_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!abs_path) {
        path_put(&aw->pwd);
        put_pid(aw->target_pid);
        kfree(aw);
        return;
    }
    resolve_absolute_path(aw->path, &aw->pwd, abs_path, PATH_MAX);

    ret = hash_file_multi(aw->path, &aw->pwd, &digest, &ident);
    if (ret) {
        /* Couldn't open/hash it (permissions, already gone, etc.) -
         * not the job of the signature path, just skip. */
        goto out;
    }

    /* Record regardless of verdict below - if this process gets killed
     * immediately it'll never reach the unlink hook anyway, and this
     * keeps the recording logic in one place rather than duplicated
     * across the signature-match/daemon-match/clean branches. */
    av_behavior_record_exec(aw->tgid, abs_path, digest.sha256);

    if (av_sigtable_match(&digest, sig_name, sizeof(sig_name))) {
        snprintf(reason, sizeof(reason), "signature:%s", sig_name);
        av_kill(aw->target_pid, abs_path, "signature", reason, &ident);
        goto out;
    }

    /* No signature match - ask the userspace daemon (avd) for a second
     * opinion (YARA/heuristics, once those land in v0.3.0+). Fail-open:
     * if there's no daemon connected or it doesn't answer in time, we
     * fall through and log clean rather than blocking exec indefinitely
     * or killing on inconclusive information. See docs/netlink-protocol.md. */
    {
        int verdict = AV_VERDICT_CLEAN;
        char rule_name[AV_RULE_NAME_MAXLEN + 1] = "";
        int nl_ret;

        nl_ret = av_netlink_scan_request(abs_path, digest.sha256,
                                          pid_nr(aw->target_pid),
                                          &verdict, rule_name,
                                          sizeof(rule_name),
                                          DAEMON_TIMEOUT_MS);
        if (nl_ret == 0 && verdict == AV_VERDICT_MALICIOUS) {
            snprintf(reason, sizeof(reason), "daemon:%s", rule_name);
            av_kill(aw->target_pid, abs_path, "daemon", reason, &ident);
        } else if (nl_ret == 0) {
            /* pr_info_ratelimited, not plain pr_info: this fires for
             * every exec that reaches the daemon path (i.e. every
             * clean, non-signature-matched exec on the system), which
             * used to mean an unconditional dmesg line per exec.
             * Deliberately NOT pr_debug_ratelimited - that would make
             * it a silent no-op by default (needs CONFIG_DYNAMIC_DEBUG
             * enabled per call site, which this project doesn't set
             * up anywhere, and would also break test_detection.sh's
             * dmesg grep for this exact line below). _ratelimited()
             * keeps it visible at its current pr_info level while
             * capping it to the kernel's default rate limit
             * (10 msgs/5s) instead of one line per exec. */
            pr_info_ratelimited("kernel-av: event=clean type=daemon path=\"%s\" "
                    "pid=%d md5=%s sha1=%s sha256=%s dev=%u:%u ino=%lu\n",
                    abs_path, pid_nr(aw->target_pid),
                    digest.md5, digest.sha1, digest.sha256,
                    MAJOR(ident.dev), MINOR(ident.dev), ident.ino);
        } else {
            /* -ENOTCONN (no daemon), -ETIMEDOUT, or another error -
             * fail open, but log distinctly so this is visible/greppable
             * separately from a genuine daemon-confirmed clean verdict.
             * Same pr_info_ratelimited reasoning as above. */
            pr_info_ratelimited("kernel-av: event=clean type=fail-open path=\"%s\" "
                    "pid=%d md5=%s sha1=%s sha256=%s err=%d\n",
                    abs_path, pid_nr(aw->target_pid),
                    digest.md5, digest.sha1, digest.sha256, nl_ret);
        }
    }

out:
    kfree(abs_path);
    path_put(&aw->pwd);
    put_pid(aw->target_pid);
    kfree(aw);
}

/* Atomic context - the ONLY things allowed here: copying small amounts
 * of data with GFP_ATOMIC, reading regs, and scheduling work. */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;
    const char __user *user_filename;
    struct av_work *aw;

    if (!real_regs)
        return 0;

    user_filename = (const char __user *)real_regs->di;
    if (!user_filename)
        return 0;

    aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
    if (!aw)
        return 0;

    /* strncpy_from_user() returns the copied length (excluding NUL) on
     * success, a negative errno on fault - but if the source string is
     * >= PATH_MAX bytes, it returns exactly PATH_MAX with NO guarantee
     * the destination is NUL-terminated. Checking only "<= 0" lets that
     * truncation case through as "success", leaving aw->path as a
     * non-NUL-terminated buffer that filp_open()/strcmp()/strstr()
     * further down would read past. Reject anything that fills the
     * whole buffer, not just outright failures. */
    {
        ssize_t path_len = strncpy_from_user(aw->path, user_filename, PATH_MAX);

        if (path_len <= 0 || path_len >= PATH_MAX) {
            kfree(aw);
            return 0;
        }
    }

    aw->target_pid = get_task_pid(current, PIDTYPE_PID);
    aw->tgid = task_tgid_nr(current);
    /* get_fs_pwd() takes fs->lock and bumps refcounts under it - no
     * sleeping, so this is fine in this atomic kprobe context. This is
     * the fix for the relative-path evasion: capture the calling
     * process's cwd HERE, while we're still running in its context,
     * so a relative aw->path can be resolved correctly later even
     * though av_work_fn() runs on a workqueue thread with an unrelated
     * cwd of its own. Released via path_put() in av_work_fn(). */
    get_fs_pwd(current->fs, &aw->pwd);
    INIT_WORK(&aw->work, av_work_fn);
    queue_work(av_wq, &aw->work);

    return 0;
}

/* ---- openat: write-intent open tracking (rapid modification +
 * sensitive-path-write heuristics) ---- */

struct av_openat_work {
    struct work_struct work;
    struct pid *target_pid;
    pid_t pid; /* actually the tgid (thread-group/process ID), not the
                * calling thread's individual pid - see task_tgid_nr()
                * below. behavior.c's tracking table is keyed by this
                * value, and current->pid is the kernel's per-THREAD
                * id: keying by it let a multi-threaded process evade
                * the rapid-write-open threshold by simply spreading
                * writes across threads, since each thread got its own
                * independent counter. */
    int flags;
    struct path base; /* dfd resolved to a struct path at kprobe time -
                        * see resolve_dfd_path(). `path` below is
                        * resolved against THIS in av_openat_work_fn(),
                        * not against whatever cwd the workqueue thread
                        * happens to have - same reasoning as av_work's
                        * pwd field. Released via path_put() in
                        * av_openat_work_fn()'s cleanup. */
    char path[PATH_MAX];
};

static void av_openat_work_fn(struct work_struct *w)
{
    struct av_openat_work *ow = container_of(w, struct av_openat_work, work);
    char *abs_path = kmalloc(PATH_MAX, GFP_KERNEL);

    if (!abs_path) {
        path_put(&ow->base);
        put_pid(ow->target_pid);
        kfree(ow);
        return;
    }

    resolve_absolute_path(ow->path, &ow->base, abs_path, PATH_MAX);
    av_behavior_check_openat(ow->pid, abs_path, ow->flags, ow->target_pid);

    kfree(abs_path);
    path_put(&ow->base);
    put_pid(ow->target_pid);
    kfree(ow);
}

/* openat(int dfd, const char *filename, int flags, umode_t mode) - on
 * the x86_64 syscall ABI, dfd is the FIRST argument (regs->di) and
 * filename is the SECOND (regs->si), unlike execve where the filename
 * is the first (regs->di). Getting this register mapping wrong is a
 * silent, hard-to-notice bug (you'd just never see openat events, no
 * crash) - verify with a kprobe_log-style dmesg print if this hook
 * seems to never fire.
 *
 * dfd is now captured and resolved (resolve_dfd_path()) rather than
 * ignored: a bare filename is only ever cwd-relative when dfd ==
 * AT_FDCWD - openat(fd_for_some_other_dir, "shadow", ...) is relative
 * to THAT fd's directory, and treating it as cwd-relative (or, as
 * before this fix, not resolving it at all) let a caller reach
 * /etc/shadow while behavior.c only ever saw the bare string
 * "shadow". */
static int handler_pre_openat(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;
    const char __user *user_filename;
    int dfd;
    int flags;
    struct av_openat_work *ow;
    struct path base;

    if (!real_regs)
        return 0;

    user_filename = (const char __user *)real_regs->si;
    if (!user_filename)
        return 0;

    dfd = (int)real_regs->di;
    flags = (int)real_regs->dx;
    /* Skip the allocation/copy entirely for read-only opens - this is
     * the overwhelming majority of opens on a normal system, and
     * filtering here (still atomic-safe - just an integer test) avoids
     * scheduling work for events behavior.c would discard anyway. */
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return 0;

    /* Resolve dfd BEFORE allocating/copying anything else - if the fd
     * doesn't resolve (bogus/racing close) there's nothing useful to
     * queue work for. */
    if (!resolve_dfd_path(dfd, &base))
        return 0;

    ow = kmalloc(sizeof(*ow), GFP_ATOMIC);
    if (!ow) {
        path_put(&base);
        return 0;
    }
    ow->base = base;

    {
        ssize_t path_len = strncpy_from_user(ow->path, user_filename, PATH_MAX);

        if (path_len <= 0 || path_len >= PATH_MAX) {
            path_put(&ow->base);
            kfree(ow);
            return 0;
        }
    }

    ow->flags = flags;
    ow->pid = task_tgid_nr(current);
    ow->target_pid = get_task_pid(current, PIDTYPE_PID);
    INIT_WORK(&ow->work, av_openat_work_fn);
    queue_work(av_wq, &ow->work);

    return 0;
}

/* ---- unlink/unlinkat: self-delete + sensitive-path-deletion ---- */

struct av_unlink_work {
    struct work_struct work;
    struct pid *target_pid;
    pid_t pid; /* tgid, not thread pid - see the note on av_openat_work
                * above; self-delete correlation against exec_path
                * needs to match the same key av_behavior_record_exec()
                * used. */
    struct path base; /* dfd resolved at kprobe time - see
                        * resolve_dfd_path(). For plain unlink() (no
                        * dfd arg) this is always the cwd capture, same
                        * as AT_FDCWD would give unlinkat(). Released
                        * via path_put() in av_unlink_work_fn(). */
    char path[PATH_MAX];
};

static void av_unlink_work_fn(struct work_struct *w)
{
    struct av_unlink_work *uw = container_of(w, struct av_unlink_work, work);
    char *abs_path = kmalloc(PATH_MAX, GFP_KERNEL);

    if (!abs_path) {
        path_put(&uw->base);
        put_pid(uw->target_pid);
        kfree(uw);
        return;
    }

    resolve_absolute_path(uw->path, &uw->base, abs_path, PATH_MAX);
    av_behavior_check_unlink(uw->pid, abs_path, uw->target_pid);

    kfree(abs_path);
    path_put(&uw->base);
    put_pid(uw->target_pid);
    kfree(uw);
}

/* `dfd` should be AT_FDCWD for plain unlink() (no base fd of its own -
 * always cwd-relative) or the real dfd argument for unlinkat(). Same
 * dfd-ignored evasion fix as openat: unlinkat(fd_for_/etc, "shadow", 0)
 * previously reached behavior.c as bare "shadow", so it could never
 * match /etc/shadow's sensitive-path check, and could never correlate
 * against an exec_path recorded as an absolute path either. */
static int schedule_unlink_work(const char __user *user_path, int dfd)
{
    struct av_unlink_work *uw;
    struct path base;

    if (!user_path)
        return 0;

    if (!resolve_dfd_path(dfd, &base))
        return 0;

    uw = kmalloc(sizeof(*uw), GFP_ATOMIC);
    if (!uw) {
        path_put(&base);
        return 0;
    }
    uw->base = base;

    {
        ssize_t path_len = strncpy_from_user(uw->path, user_path, PATH_MAX);

        if (path_len <= 0 || path_len >= PATH_MAX) {
            path_put(&uw->base);
            kfree(uw);
            return 0;
        }
    }

    uw->pid = task_tgid_nr(current);
    uw->target_pid = get_task_pid(current, PIDTYPE_PID);
    INIT_WORK(&uw->work, av_unlink_work_fn);
    queue_work(av_wq, &uw->work);

    return 0;
}

/* unlink(const char *pathname) - pathname is the first (and only)
 * argument, same register position as execve's filename. No dfd of
 * its own, so always resolves relative to cwd (AT_FDCWD). */
static int handler_pre_unlink(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    if (!real_regs)
        return 0;
    return schedule_unlink_work((const char __user *)real_regs->di, AT_FDCWD);
}

/* unlinkat(int dfd, const char *pathname, int flag) - dfd is the FIRST
 * argument (regs->di), pathname is the SECOND (regs->si), same
 * position as openat's filename. */
static int handler_pre_unlinkat(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    if (!real_regs)
        return 0;
    return schedule_unlink_work((const char __user *)real_regs->si,
                                 (int)real_regs->di);
}

/* ---- rename/renameat/renameat2: extension-append burst + sensitive-
 * path rename tracking. Same atomic-context discipline as every other
 * hook here: pre-handlers only copy TWO path strings (GFP_ATOMIC) and
 * schedule work; all logic lives in av_behavior_check_rename(). ---- */

struct av_rename_work {
    struct work_struct work;
    struct pid *target_pid;
    pid_t pid; /* tgid, not thread pid - see the note on av_openat_work
                * above; keeps the rename counter keyed the same way
                * as every other per-process heuristic here. */
    struct path old_base; /* olddfd resolved at kprobe time (AT_FDCWD
                            * for rename(), which has no dfd args of
                            * its own). old_base/new_base are
                            * deliberately independent - renameat()
                            * allows olddfd and newdfd to name
                            * different directories entirely, so
                            * oldpath and newpath cannot share a single
                            * resolved base the way openat/unlink can.
                            * Released via path_put() in
                            * av_rename_work_fn(). */
    struct path new_base; /* newdfd resolved at kprobe time - see
                            * old_base above. */
    char oldpath[PATH_MAX];
    char newpath[PATH_MAX];
};

static void av_rename_work_fn(struct work_struct *w)
{
    struct av_rename_work *rw = container_of(w, struct av_rename_work, work);
    char *abs_old = kmalloc(PATH_MAX, GFP_KERNEL);
    char *abs_new;

    if (!abs_old) {
        path_put(&rw->old_base);
        path_put(&rw->new_base);
        put_pid(rw->target_pid);
        kfree(rw);
        return;
    }
    abs_new = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!abs_new) {
        kfree(abs_old);
        path_put(&rw->old_base);
        path_put(&rw->new_base);
        put_pid(rw->target_pid);
        kfree(rw);
        return;
    }

    resolve_absolute_path(rw->oldpath, &rw->old_base, abs_old, PATH_MAX);
    resolve_absolute_path(rw->newpath, &rw->new_base, abs_new, PATH_MAX);
    av_behavior_check_rename(rw->pid, abs_old, abs_new, rw->target_pid);

    kfree(abs_new);
    kfree(abs_old);
    path_put(&rw->old_base);
    path_put(&rw->new_base);
    put_pid(rw->target_pid);
    kfree(rw);
}

/* `olddfd`/`newdfd` should each be AT_FDCWD for rename() (no dfd args
 * of its own - both ends are always cwd-relative) or the real dfd
 * arguments for renameat()/renameat2(). Same dfd-ignored evasion fix
 * as openat/unlink: renameat(fd_for_/etc, "shadow", fd_for_/tmp,
 * "leaked") previously reached behavior.c as bare "shadow"/"leaked",
 * bypassing the sensitive-path check on the oldpath end entirely. */
static int schedule_rename_work(const char __user *user_oldpath, int olddfd,
                                 const char __user *user_newpath, int newdfd)
{
    struct av_rename_work *rw;
    struct path old_base, new_base;

    if (!user_oldpath || !user_newpath)
        return 0;

    if (!resolve_dfd_path(olddfd, &old_base))
        return 0;
    if (!resolve_dfd_path(newdfd, &new_base)) {
        path_put(&old_base);
        return 0;
    }

    rw = kmalloc(sizeof(*rw), GFP_ATOMIC);
    if (!rw) {
        path_put(&old_base);
        path_put(&new_base);
        return 0;
    }
    rw->old_base = old_base;
    rw->new_base = new_base;

    {
        ssize_t path_len;

        path_len = strncpy_from_user(rw->oldpath, user_oldpath, PATH_MAX);
        if (path_len <= 0 || path_len >= PATH_MAX) {
            path_put(&rw->old_base);
            path_put(&rw->new_base);
            kfree(rw);
            return 0;
        }
        path_len = strncpy_from_user(rw->newpath, user_newpath, PATH_MAX);
        if (path_len <= 0 || path_len >= PATH_MAX) {
            path_put(&rw->old_base);
            path_put(&rw->new_base);
            kfree(rw);
            return 0;
        }
    }

    rw->pid = task_tgid_nr(current);
    rw->target_pid = get_task_pid(current, PIDTYPE_PID);
    INIT_WORK(&rw->work, av_rename_work_fn);
    queue_work(av_wq, &rw->work);

    return 0;
}

/* rename(const char *oldname, const char *newname) - same register
 * shape as unlink's single-arg case, just two of them: oldname is the
 * first arg (di), newname is the second (si). No dfd args of its own,
 * so both resolve relative to cwd (AT_FDCWD). */
static int handler_pre_rename(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    if (!real_regs)
        return 0;
    return schedule_rename_work((const char __user *)real_regs->di, AT_FDCWD,
                                 (const char __user *)real_regs->si, AT_FDCWD);
}

/* renameat(int olddfd, const char *oldname, int newdfd, const char *newname)
 * - olddfd is the FIRST arg (di), oldname the SECOND (si), newdfd the
 * THIRD (dx), newname the FOURTH (r10, not r8 - standard x86_64
 * syscall arg order is di/si/dx/r10/r8/r9, since r10 substitutes for
 * rcx which the SYSCALL instruction itself clobbers). */
static int handler_pre_renameat(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    if (!real_regs)
        return 0;
    return schedule_rename_work((const char __user *)real_regs->si,
                                 (int)real_regs->di,
                                 (const char __user *)real_regs->r10,
                                 (int)real_regs->dx);
}

/* renameat2(int olddfd, const char *oldname, int newdfd, const char *newname,
 * unsigned int flags) - same first four args as renameat (flags, the
 * fifth/r8, isn't currently used - RENAME_EXCHANGE/RENAME_NOREPLACE/
 * RENAME_WHITEOUT aren't distinguished by this heuristic today). */
static int handler_pre_renameat2(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    if (!real_regs)
        return 0;
    return schedule_rename_work((const char __user *)real_regs->si,
                                 (int)real_regs->di,
                                 (const char __user *)real_regs->r10,
                                 (int)real_regs->dx);
}

static int __init av_init(void)
{
    int ret;

    ret = av_sigtable_init();
    if (ret)
        return ret;

    ret = av_sigtable_proc_init();
    if (ret) {
        pr_err("kernel-av: failed to create /proc/kernel_av_signatures: %d\n", ret);
        goto err_sigtable;
    }

    /* Seed a default signature so testing works out of the box without
     * needing a separate `avctl add` step first. */
    av_sigtable_add(AV_ALGO_SHA256,
                     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                     "EICAR-Test-File");

    ret = av_behavior_init();
    if (ret) {
        pr_err("kernel-av: failed to init behavior tracking: %d\n", ret);
        goto err_proc;
    }

    av_wq = alloc_workqueue("kernel_av_wq", WQ_UNBOUND, 0);
    if (!av_wq) {
        pr_err("kernel-av: failed to allocate workqueue\n");
        ret = -ENOMEM;
        goto err_behavior;
    }

    ret = av_netlink_init();
    if (ret) {
        pr_err("kernel-av: failed to register netlink family: %d\n", ret);
        goto err_wq;
    }

    kp_execve.pre_handler = handler_pre;
    ret = register_kprobe(&kp_execve);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe(execve) failed: %d\n", ret);
        goto err_netlink;
    }

    kp_openat.pre_handler = handler_pre_openat;
    ret = register_kprobe(&kp_openat);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe(openat) failed: %d\n", ret);
        goto err_kp_execve;
    }

    kp_unlink.pre_handler = handler_pre_unlink;
    ret = register_kprobe(&kp_unlink);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe(unlink) failed: %d\n", ret);
        goto err_kp_openat;
    }

    kp_unlinkat.pre_handler = handler_pre_unlinkat;
    ret = register_kprobe(&kp_unlinkat);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe(unlinkat) failed: %d\n", ret);
        goto err_kp_unlink;
    }

    kp_rename.pre_handler = handler_pre_rename;
    ret = register_kprobe(&kp_rename);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe(rename) failed: %d\n", ret);
        goto err_kp_unlinkat;
    }

    kp_renameat.pre_handler = handler_pre_renameat;
    ret = register_kprobe(&kp_renameat);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe(renameat) failed: %d\n", ret);
        goto err_kp_rename;
    }

    kp_renameat2.pre_handler = handler_pre_renameat2;
    ret = register_kprobe(&kp_renameat2);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe(renameat2) failed: %d\n", ret);
        goto err_kp_renameat;
    }

    pr_info("kernel-av: loaded, %zu signature(s) active\n", av_sigtable_count());
    return 0;

err_kp_renameat:
    unregister_kprobe(&kp_renameat);
err_kp_rename:
    unregister_kprobe(&kp_rename);
err_kp_unlinkat:
    unregister_kprobe(&kp_unlinkat);
err_kp_unlink:
    unregister_kprobe(&kp_unlink);
err_kp_openat:
    unregister_kprobe(&kp_openat);
err_kp_execve:
    unregister_kprobe(&kp_execve);
err_netlink:
    av_netlink_exit();
err_wq:
    destroy_workqueue(av_wq);
err_behavior:
    av_behavior_exit();
err_proc:
    av_sigtable_proc_exit();
err_sigtable:
    av_sigtable_exit();
    return ret;
}

static void __exit av_exit(void)
{
    unregister_kprobe(&kp_renameat2);
    unregister_kprobe(&kp_renameat);
    unregister_kprobe(&kp_rename);
    unregister_kprobe(&kp_unlinkat);
    unregister_kprobe(&kp_unlink);
    unregister_kprobe(&kp_openat);
    unregister_kprobe(&kp_execve);
    /* destroy_workqueue() flushes all pending work first, so no work
     * item can run against unloaded module .text after this returns. */
    destroy_workqueue(av_wq);
    av_netlink_exit();
    av_behavior_exit();
    av_sigtable_proc_exit();
    av_sigtable_exit();
    pr_info("kernel-av: unloaded\n");
}

module_init(av_init);
module_exit(av_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Signature-based execve detection with runtime-managed signature DB and behavioral heuristics");
MODULE_VERSION("1.0.0");
