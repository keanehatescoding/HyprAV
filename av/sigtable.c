/*
 * sigtable.c - hashtable-backed signature store + /proc interface.
 *
 * Locking: everything here runs in process context (the /proc write
 * comes from a userspace syscall; the match lookup runs from our
 * workqueue - see main.c) so a plain mutex is enough. No spinlocks/RCU
 * needed at this stage.
 *
 * /proc/kernel_av_signatures usage:
 *   cat  /proc/kernel_av_signatures                  - list entries
 *   echo "add sha256 <hex> <name>" > .../kernel_av_signatures
 *   echo "del sha256 <hex>"        > .../kernel_av_signatures
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#include "sigtable.h"

struct av_sig_entry {
    struct hlist_node node;
    enum av_algo algo;
    char name[AV_SIG_NAME_LEN];
    char hex[AV_HASH_HEX_MAXLEN + 1];
};

#define SIGTABLE_BITS 10 /* 1024 buckets - plenty for a student-scale DB */
static DEFINE_HASHTABLE(sig_table, SIGTABLE_BITS);
static DEFINE_MUTEX(sig_lock);
static size_t sig_count;

static const size_t algo_hexlen[AV_ALGO_COUNT] = { 32, 40, 64 };
static const char * const algo_names[AV_ALGO_COUNT] = { "md5", "sha1", "sha256" };

static u32 hex_key(const char *hex)
{
    return full_name_hash(NULL, hex, strlen(hex));
}

static const char *digest_for_algo(const struct av_digest *d, enum av_algo algo)
{
    switch (algo) {
    case AV_ALGO_MD5:    return d->md5;
    case AV_ALGO_SHA1:   return d->sha1;
    case AV_ALGO_SHA256: return d->sha256;
    default:             return NULL;
    }
}

static int parse_algo(const char *s, enum av_algo *out)
{
    if (!strcasecmp(s, "md5"))         *out = AV_ALGO_MD5;
    else if (!strcasecmp(s, "sha1"))   *out = AV_ALGO_SHA1;
    else if (!strcasecmp(s, "sha256")) *out = AV_ALGO_SHA256;
    else return -EINVAL;
    return 0;
}

int av_sigtable_add(enum av_algo algo, const char *hex, const char *name)
{
    struct av_sig_entry *e;

    if (algo >= AV_ALGO_COUNT)
        return -EINVAL;
    if (strlen(hex) != algo_hexlen[algo])
        return -EINVAL;

    e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return -ENOMEM;

    e->algo = algo;
    strscpy(e->hex, hex, sizeof(e->hex));
    strscpy(e->name, name, sizeof(e->name));

    mutex_lock(&sig_lock);
    hash_add(sig_table, &e->node, hex_key(hex));
    sig_count++;
    mutex_unlock(&sig_lock);

    return 0;
}

int av_sigtable_del(enum av_algo algo, const char *hex)
{
    struct av_sig_entry *e;
    int ret = -ENOENT;

    mutex_lock(&sig_lock);
    hash_for_each_possible(sig_table, e, node, hex_key(hex)) {
        if (e->algo == algo && !strncasecmp(e->hex, hex, algo_hexlen[algo])) {
            hash_del(&e->node);
            kfree(e);
            sig_count--;
            ret = 0;
            break;
        }
    }
    mutex_unlock(&sig_lock);
    return ret;
}

int av_sigtable_match(const struct av_digest *d, char *name_out, size_t name_out_len)
{
    struct av_sig_entry *e;
    int algo;
    int found = 0;

    mutex_lock(&sig_lock);
    for (algo = 0; algo < AV_ALGO_COUNT; algo++) {
        const char *hex = digest_for_algo(d, algo);

        hash_for_each_possible(sig_table, e, node, hex_key(hex)) {
            if (e->algo == algo &&
                !strncasecmp(e->hex, hex, algo_hexlen[algo])) {
                strscpy(name_out, e->name, name_out_len);
                found = 1;
                goto out;
            }
        }
    }
out:
    mutex_unlock(&sig_lock);
    return found;
}

size_t av_sigtable_count(void)
{
    return sig_count; /* informational only - fine without the lock */
}

/* ---- /proc interface ---- */

static int sig_proc_show(struct seq_file *m, void *v)
{
    struct av_sig_entry *e;
    int bkt;

    mutex_lock(&sig_lock);
    hash_for_each(sig_table, bkt, e, node)
        seq_printf(m, "%s %s %s\n", algo_names[e->algo], e->hex, e->name);
    mutex_unlock(&sig_lock);
    return 0;
}

static int sig_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, sig_proc_show, NULL);
}

static ssize_t sig_proc_write(struct file *file, const char __user *ubuf,
                               size_t count, loff_t *ppos)
{
    char kbuf[256];
    char cmd[8], algo_str[8], hex[AV_HASH_HEX_MAXLEN + 1], name[AV_SIG_NAME_LEN];
    enum av_algo algo;
    size_t len = min(count, sizeof(kbuf) - 1);
    int n;

    if (copy_from_user(kbuf, ubuf, len))
        return -EFAULT;
    kbuf[len] = '\0';

    n = sscanf(kbuf, "%7s %7s %64s %63[^\n]", cmd, algo_str, hex, name);
    if (n < 3)
        return -EINVAL;

    if (parse_algo(algo_str, &algo))
        return -EINVAL;

    if (!strcasecmp(cmd, "add")) {
        if (n < 4)
            return -EINVAL;
        if (av_sigtable_add(algo, hex, name))
            return -EINVAL;
    } else if (!strcasecmp(cmd, "del")) {
        if (av_sigtable_del(algo, hex))
            return -ENOENT;
    } else {
        return -EINVAL;
    }

    return count;
}

static const struct proc_ops sig_proc_ops = {
    .proc_open    = sig_proc_open,
    .proc_read    = seq_read,
    .proc_write   = sig_proc_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static struct proc_dir_entry *sig_proc_entry;

int av_sigtable_proc_init(void)
{
    sig_proc_entry = proc_create("kernel_av_signatures", 0644, NULL, &sig_proc_ops);
    if (!sig_proc_entry)
        return -ENOMEM;
    return 0;
}

void av_sigtable_proc_exit(void)
{
    proc_remove(sig_proc_entry);
}

int av_sigtable_init(void)
{
    hash_init(sig_table);
    return 0;
}

void av_sigtable_exit(void)
{
    struct av_sig_entry *e;
    struct hlist_node *tmp;
    int bkt;

    mutex_lock(&sig_lock);
    hash_for_each_safe(sig_table, bkt, tmp, e, node) {
        hash_del(&e->node);
        kfree(e);
    }
    mutex_unlock(&sig_lock);
}
