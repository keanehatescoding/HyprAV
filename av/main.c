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
    .symbol_name = "__x64_sys_execve",
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

static struct workqueue_struct *av_wq;

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
 * read pass. MUST be called from a sleepable (process) context only. */
static int hash_file_multi(const char *path, const struct path *pwd,
                            struct av_digest *out)
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
                     const char *type, const char *reason)
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
                 "path=\"%s\" reason=\"%s\" pid=%d\n",
                 type, path, reason, pid_nr(target_pid));
        send_sig(SIGKILL, task, 0);
    }
    rcu_read_unlock();
}

/* Runs in a kernel worker thread - safe to sleep, do file I/O, use
 * GFP_KERNEL. This is where all "heavy" work happens. */
static void av_work_fn(struct work_struct *w)
{
    struct av_work *aw = container_of(w, struct av_work, work);
    struct av_digest digest;
    char sig_name[AV_SIG_NAME_LEN];
    char reason[AV_SIG_NAME_LEN + 32];
    int ret;

    ret = hash_file_multi(aw->path, &aw->pwd, &digest);
    if (ret) {
        /* Couldn't open/hash it (permissions, already gone, etc.) -
         * not the job of the signature path, just skip. */
        goto out;
    }

    /* Record regardless of verdict below - if this process gets killed
     * immediately it'll never reach the unlink hook anyway, and this
     * keeps the recording logic in one place rather than duplicated
     * across the signature-match/daemon-match/clean branches. */
    av_behavior_record_exec(aw->tgid, aw->path, digest.sha256);

    if (av_sigtable_match(&digest, sig_name, sizeof(sig_name))) {
        snprintf(reason, sizeof(reason), "signature:%s", sig_name);
        av_kill(aw->target_pid, aw->path, "signature", reason);
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

        nl_ret = av_netlink_scan_request(aw->path, digest.sha256,
                                          pid_nr(aw->target_pid),
                                          &verdict, rule_name,
                                          sizeof(rule_name),
                                          DAEMON_TIMEOUT_MS);
        if (nl_ret == 0 && verdict == AV_VERDICT_MALICIOUS) {
            snprintf(reason, sizeof(reason), "daemon:%s", rule_name);
            av_kill(aw->target_pid, aw->path, "daemon", reason);
        } else if (nl_ret == 0) {
            pr_info("kernel-av: event=clean type=daemon path=\"%s\" pid=%d "
                    "md5=%s sha1=%s sha256=%s\n",
                    aw->path, pid_nr(aw->target_pid),
                    digest.md5, digest.sha1, digest.sha256);
        } else {
            /* -ENOTCONN (no daemon), -ETIMEDOUT, or another error -
             * fail open, but log distinctly so this is visible/greppable
             * separately from a genuine daemon-confirmed clean verdict. */
            pr_info("kernel-av: event=clean type=fail-open path=\"%s\" "
                    "pid=%d md5=%s sha1=%s sha256=%s err=%d\n",
                    aw->path, pid_nr(aw->target_pid),
                    digest.md5, digest.sha1, digest.sha256, nl_ret);
        }
    }

out:
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
    char path[PATH_MAX];
};

static void av_openat_work_fn(struct work_struct *w)
{
    struct av_openat_work *ow = container_of(w, struct av_openat_work, work);

    av_behavior_check_openat(ow->pid, ow->path, ow->flags, ow->target_pid);

    put_pid(ow->target_pid);
    kfree(ow);
}

/* openat(int dfd, const char *filename, int flags, umode_t mode) - on
 * the x86_64 syscall ABI, filename is the SECOND argument (regs->si),
 * unlike execve where the filename is the first (regs->di). Getting
 * this register mapping wrong is a silent, hard-to-notice bug (you'd
 * just never see openat events, no crash) - verify with a kprobe_log-
 * style dmesg print if this hook seems to never fire. */
static int handler_pre_openat(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;
    const char __user *user_filename;
    int flags;
    struct av_openat_work *ow;

    if (!real_regs)
        return 0;

    user_filename = (const char __user *)real_regs->si;
    if (!user_filename)
        return 0;

    flags = (int)real_regs->dx;
    /* Skip the allocation/copy entirely for read-only opens - this is
     * the overwhelming majority of opens on a normal system, and
     * filtering here (still atomic-safe - just an integer test) avoids
     * scheduling work for events behavior.c would discard anyway. */
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return 0;

    ow = kmalloc(sizeof(*ow), GFP_ATOMIC);
    if (!ow)
        return 0;

    {
        ssize_t path_len = strncpy_from_user(ow->path, user_filename, PATH_MAX);

        if (path_len <= 0 || path_len >= PATH_MAX) {
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
    char path[PATH_MAX];
};

static void av_unlink_work_fn(struct work_struct *w)
{
    struct av_unlink_work *uw = container_of(w, struct av_unlink_work, work);

    av_behavior_check_unlink(uw->pid, uw->path, uw->target_pid);

    put_pid(uw->target_pid);
    kfree(uw);
}

static int schedule_unlink_work(const char __user *user_path)
{
    struct av_unlink_work *uw;

    if (!user_path)
        return 0;

    uw = kmalloc(sizeof(*uw), GFP_ATOMIC);
    if (!uw)
        return 0;

    {
        ssize_t path_len = strncpy_from_user(uw->path, user_path, PATH_MAX);

        if (path_len <= 0 || path_len >= PATH_MAX) {
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
 * argument, same register position as execve's filename. */
static int handler_pre_unlink(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    if (!real_regs)
        return 0;
    return schedule_unlink_work((const char __user *)real_regs->di);
}

/* unlinkat(int dfd, const char *pathname, int flag) - pathname is the
 * SECOND argument (regs->si), same position as openat's filename. */
static int handler_pre_unlinkat(struct kprobe *p, struct pt_regs *regs)
{
    const struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    if (!real_regs)
        return 0;
    return schedule_unlink_work((const char __user *)real_regs->si);
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

    pr_info("kernel-av: loaded, %zu signature(s) active\n", av_sigtable_count());
    return 0;

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
MODULE_VERSION("0.8-pre");
