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
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/sched/signal.h>
#include <linux/workqueue.h>
#include <linux/pid.h>

#include "sigtable.h"

#define HOOKED_SYSCALL_NAME "__x64_sys_execve" /* see README re: arch */
#define READ_CHUNK_SIZE     4096

static struct kprobe kp = {
    .symbol_name = HOOKED_SYSCALL_NAME,
};

static struct workqueue_struct *av_wq;

struct av_work {
    struct work_struct work;
    struct pid *target_pid;
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

/* Computes MD5, SHA-1, and SHA-256 of the file at `path` in a single
 * read pass. MUST be called from a sleepable (process) context only. */
static int hash_file_multi(const char *path, struct av_digest *out)
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

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return PTR_ERR(f);

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

/* Runs in a kernel worker thread - safe to sleep, do file I/O, use
 * GFP_KERNEL. This is where all "heavy" work happens. */
static void av_work_fn(struct work_struct *w)
{
    struct av_work *aw = container_of(w, struct av_work, work);
    struct av_digest digest;
    char sig_name[AV_SIG_NAME_LEN];
    struct task_struct *task;
    int ret;

    ret = hash_file_multi(aw->path, &digest);
    if (ret) {
        /* Couldn't open/hash it (permissions, already gone, etc.) -
         * not the job of the signature path, just skip. */
        goto out;
    }

    if (av_sigtable_match(&digest, sig_name, sizeof(sig_name))) {
        rcu_read_lock();
        task = pid_task(aw->target_pid, PIDTYPE_PID);
        if (task) {
            pr_alert("kernel-av: DETECTED \"%s\" matches signature \"%s\" "
                     "(pid %d) - killing\n",
                     aw->path, sig_name, pid_nr(aw->target_pid));
            send_sig(SIGKILL, task, 0);
        }
        rcu_read_unlock();
    } else {
        pr_info("kernel-av: execve(\"%s\") md5=%s sha1=%s sha256=%s clean\n",
                aw->path, digest.md5, digest.sha1, digest.sha256);
    }

out:
    put_pid(aw->target_pid);
    kfree(aw);
}

/* Atomic context - the ONLY things allowed here: copying small amounts
 * of data with GFP_ATOMIC, reading regs, and scheduling work. */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = (struct pt_regs *)regs->di;
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

    if (strncpy_from_user(aw->path, user_filename, PATH_MAX) <= 0) {
        kfree(aw);
        return 0;
    }

    aw->target_pid = get_task_pid(current, PIDTYPE_PID);
    INIT_WORK(&aw->work, av_work_fn);
    queue_work(av_wq, &aw->work);

    return 0;
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

    av_wq = alloc_workqueue("kernel_av_wq", WQ_UNBOUND, 0);
    if (!av_wq) {
        pr_err("kernel-av: failed to allocate workqueue\n");
        ret = -ENOMEM;
        goto err_proc;
    }

    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe failed: %d\n", ret);
        goto err_wq;
    }

    pr_info("kernel-av: loaded, %zu signature(s) active\n", av_sigtable_count());
    return 0;

err_wq:
    destroy_workqueue(av_wq);
err_proc:
    av_sigtable_proc_exit();
err_sigtable:
    av_sigtable_exit();
    return ret;
}

static void __exit av_exit(void)
{
    unregister_kprobe(&kp);
    /* destroy_workqueue() flushes all pending work first, so no work
     * item can run against unloaded module .text after this returns. */
    destroy_workqueue(av_wq);
    av_sigtable_proc_exit();
    av_sigtable_exit();
    pr_info("kernel-av: unloaded\n");
}

module_init(av_init);
module_exit(av_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Signature-based execve detection with runtime-managed signature DB");
MODULE_VERSION("0.2");
