/*
 * av module - kprobe on execve, in-kernel SHA-256 hashing,
 * hardcoded signature match, kill on detection.
 *
 * Flow:
 *   1. kprobe fires before execve runs, giving us the target file path
 *   2. open the file in-kernel and stream it through the kernel crypto
 *      API to compute its SHA-256
 *   3. compare against known_signatures (signatures.h)
 *   4. on match: log it and SIGKILL the calling process
 *
 * KNOWN LIMITATION (be upfront about this in your report): a kprobe
 * pre-handler cannot cleanly deny the syscall the way an LSM hook can -
 * we're killing the process right after we detect it, which means there's
 * a brief race where the binary may begin executing before the kill lands.
 * For this milestone this is an accepted simplification; discuss it as a
 * design tradeoff, and consider migrating to an LSM hook (security_bprm_
 * check_security) in a later stage for a real pre-exec deny.
 *
 * Build:   make
 * Load:    sudo insmod av.ko
 * Test:    create /tmp/eicar.com (see top-level README), then run it
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

#include "signatures.h"

#define HOOKED_SYSCALL_NAME "__x64_sys_execve" /* see README re: arch */
#define READ_CHUNK_SIZE     4096
#define SHA256_DIGEST_SIZE  32

static struct kprobe kp = {
    .symbol_name = HOOKED_SYSCALL_NAME,
};

/* Compute SHA-256 of the file at `path`, writing 64 lowercase hex chars
 * (+ NUL) into out_hex. Returns 0 on success, negative errno on failure. */
static int hash_file_sha256(const char *path, char *out_hex, size_t out_hex_len)
{
    struct file *f;
    struct crypto_shash *tfm = NULL;
    struct shash_desc *desc = NULL;
    void *buf = NULL;
    u8 digest[SHA256_DIGEST_SIZE];
    loff_t pos = 0;
    ssize_t n;
    int ret = 0;
    int i;

    if (out_hex_len < (SHA256_DIGEST_SIZE * 2 + 1))
        return -EINVAL;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return PTR_ERR(f);

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        tfm = NULL;
        goto out;
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto out;
    }
    desc->tfm = tfm;

    buf = kmalloc(READ_CHUNK_SIZE, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    ret = crypto_shash_init(desc);
    if (ret)
        goto out;

    while ((n = kernel_read(f, buf, READ_CHUNK_SIZE, &pos)) > 0) {
        ret = crypto_shash_update(desc, buf, n);
        if (ret)
            goto out;
    }
    if (n < 0) {
        ret = n; /* read error */
        goto out;
    }

    ret = crypto_shash_final(desc, digest);
    if (ret)
        goto out;

    for (i = 0; i < SHA256_DIGEST_SIZE; i++)
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    out_hex[SHA256_DIGEST_SIZE * 2] = '\0';

out:
    kfree(buf);
    kfree(desc);
    if (tfm)
        crypto_free_shash(tfm);
    filp_close(f, NULL);
    return ret;
}

static const struct av_signature *match_signature(const char *hex_digest)
{
    int i;

    for (i = 0; i < NUM_SIGNATURES; i++) {
        if (strncasecmp(hex_digest, known_signatures[i].sha256_hex, 64) == 0)
            return &known_signatures[i];
    }
    return NULL;
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = (struct pt_regs *)regs->di;
    const char __user *user_filename;
    char *kpath;
    char hex_digest[SHA256_DIGEST_SIZE * 2 + 1];
    const struct av_signature *hit;
    int ret;

    if (!real_regs)
        return 0;

    user_filename = (const char __user *)real_regs->di;
    if (!user_filename)
        return 0;

    kpath = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!kpath)
        return 0;

    if (strncpy_from_user(kpath, user_filename, PATH_MAX) <= 0)
        goto out_free;

    ret = hash_file_sha256(kpath, hex_digest, sizeof(hex_digest));
    if (ret) {
        /* Couldn't open/hash it (permissions, doesn't exist yet, etc.) -
         * not the job of the signature path, just skip. */
        goto out_free;
    }

    hit = match_signature(hex_digest);
    if (hit) {
        pr_alert("kernel-av: DETECTED \"%s\" matches signature "
                 "\"%s\" (pid %d, comm %s) - killing\n",
                 kpath, hit->name, current->pid, current->comm);
        send_sig(SIGKILL, current, 0);
    } else {
        pr_info("kernel-av: execve(\"%s\") sha256=%s clean\n",
                kpath, hex_digest);
    }

out_free:
    kfree(kpath);
    return 0;
}

static int __init av_init(void)
{
    int ret;

    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("kernel-av: register_kprobe failed: %d\n", ret);
        return ret;
    }

    pr_info("kernel-av: loaded, %zu signature(s) active\n",
            NUM_SIGNATURES);
    return 0;
}

static void __exit av_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("kernel-av: unloaded\n");
}

module_init(av_init);
module_exit(av_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Signature-based execve detection");
MODULE_VERSION("0.1");
