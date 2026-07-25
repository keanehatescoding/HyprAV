/*
 * av module - kprobe on execve, in-kernel SHA-256 hashing,
 * hardcoded signature match, kill on detection.
 *
 * ARCHITECTURE NOTE (read this before modifying handler_pre):
 * kprobe pre-handlers run in an ATOMIC context, similar to an interrupt
 * handler - you cannot sleep, block on I/O, or use GFP_KERNEL allocations
 * in there. An earlier version of this file did file I/O and crypto work
 * directly inside handler_pre and it corrupted kernel state on every
 * execve() (manifesting as unrelated processes segfaulting). The fix:
 * handler_pre does the absolute minimum atomically-safe work (copy the
 * path, grab a reference to the target pid) and hands everything else off
 * to a workqueue, which runs in a normal sleepable process context.
 *
 * Flow:
 *   1. kprobe fires before execve runs; handler_pre copies the path and
 *      schedules a work item (atomic-safe only)
 *   2. the work item runs later, in process context: opens the file,
 *      streams it through the kernel crypto API to compute SHA-256
 *   3. compares against known_signatures (signatures.h)
 *   4. on match: logs it and SIGKILLs the target process
 *
 * KNOWN LIMITATION (be upfront about this in your report): because
 * detection happens asynchronously in a workqueue rather than as a
 * pre-exec deny, there's a window where the binary may begin executing
 * before the kill lands - the delay is now larger than the original
 * synchronous version, though the synchronous version was unsafe. A real
 * pre-exec deny needs an LSM hook (security_bprm_check_security), which
 * runs in a context that can call these APIs directly. Consider that for
 * a later milestone.
 *
 * Build:   make
 * Load:    sudo insmod av.ko
 * Test:    create /tmp/eicar.com (see top-level README), then run it
 * Check:   dmesg | tail -20
 * Unload:  sudo rmmod av
 */

#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "signatures.h"

#define HOOKED_SYSCALL_NAME "__x64_sys_execve" /* see README re: arch */
#define READ_CHUNK_SIZE 4096
#define SHA256_DIGEST_SIZE 32
#define HEX_DIGEST_LEN (SHA256_DIGEST_SIZE * 2 + 1)

static struct kprobe kp = {
    .symbol_name = HOOKED_SYSCALL_NAME,
};

/* Dedicated workqueue rather than the shared system one, so we can
 * flush_and destroy it cleanly on module unload - guarantees no work
 * item runs after our .text has been unloaded. */
static struct workqueue_struct *av_wq;

struct av_work {
  struct work_struct work;
  struct pid *target_pid; /* reference held via get_task_pid() */
  char path[PATH_MAX];
};

/* Compute SHA-256 of the file at `path`, writing 64 lowercase hex chars
 * (+ NUL) into out_hex. Returns 0 on success, negative errno on failure.
 * MUST be called from a sleepable (process) context only. */
static int hash_file_sha256(const char *path, char *out_hex,
                            size_t out_hex_len) {
  struct file *f;
  struct crypto_shash *tfm = NULL;
  struct shash_desc *desc = NULL;
  void *buf = NULL;
  u8 digest[SHA256_DIGEST_SIZE];
  loff_t pos = 0;
  ssize_t n;
  int ret = 0;
  int i;

  if (out_hex_len < HEX_DIGEST_LEN)
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

static const struct av_signature *match_signature(const char *hex_digest) {
  int i;

  for (i = 0; i < NUM_SIGNATURES; i++) {
    if (strncasecmp(hex_digest, known_signatures[i].sha256_hex, 64) == 0)
      return &known_signatures[i];
  }
  return NULL;
}

/* Runs in a kernel worker thread - normal process context, safe to sleep,
 * do file I/O, and use GFP_KERNEL. This is where all the "heavy" work
 * that used to live in handler_pre now happens. */
static void av_work_fn(struct work_struct *w) {
  struct av_work *aw = container_of(w, struct av_work, work);
  char hex_digest[HEX_DIGEST_LEN];
  const struct av_signature *hit;
  struct task_struct *task;
  int ret;

  ret = hash_file_sha256(aw->path, hex_digest, sizeof(hex_digest));
  if (ret) {
    /* Couldn't open/hash it (permissions, already gone, etc.) -
     * not the job of the signature path, just skip. */
    goto out;
  }

  hit = match_signature(hex_digest);
  if (hit) {
    rcu_read_lock();
    task = pid_task(aw->target_pid, PIDTYPE_PID);
    if (task) {
      pr_alert("kernel-av: DETECTED \"%s\" matches signature \"%s\" "
               "(pid %d) - killing\n",
               aw->path, hit->name, pid_nr(aw->target_pid));
      send_sig(SIGKILL, task, 0);
    }
    rcu_read_unlock();
  } else {
    pr_info("kernel-av: execve(\"%s\") sha256=%s clean\n", aw->path,
            hex_digest);
  }

out:
  put_pid(aw->target_pid);
  kfree(aw);
}

/* Atomic context - the ONLY things allowed here: copying small amounts
 * of data with GFP_ATOMIC, reading regs, and scheduling work. No file
 * I/O, no crypto, no GFP_KERNEL. */
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
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

  /* Take a reference to the pid (not the task_struct directly) so we
   * can safely look the task up later even if it has changed state. */
  aw->target_pid = get_task_pid(current, PIDTYPE_PID);

  INIT_WORK(&aw->work, av_work_fn);
  queue_work(av_wq, &aw->work);

  return 0;
}

static int __init av_init(void) {
  int ret;

  av_wq = alloc_workqueue("kernel_av_wq", WQ_UNBOUND, 0);
  if (!av_wq) {
    pr_err("kernel-av: failed to allocate workqueue\n");
    return -ENOMEM;
  }

  kp.pre_handler = handler_pre;

  ret = register_kprobe(&kp);
  if (ret < 0) {
    pr_err("kernel-av: register_kprobe failed: %d\n", ret);
    destroy_workqueue(av_wq);
    return ret;
  }

  pr_info("kernel-av: loaded, %zu signature(s) active\n", NUM_SIGNATURES);
  return 0;
}

static void __exit av_exit(void) {
  unregister_kprobe(&kp);
  /* destroy_workqueue() flushes all pending work first, so no work
   * item can run against freed module .text after this returns. */
  destroy_workqueue(av_wq);
  pr_info("kernel-av: unloaded\n");
}

module_init(av_init);
module_exit(av_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Signature-based execve detection");
MODULE_VERSION("0.2");
