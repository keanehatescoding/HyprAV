/*
 * stage0/kprobe_log - hook execve via kprobes and just LOG the filename.
 * No blocking, no denial — this stage is purely about proving you can
 * intercept a syscall entry point safely.
 *
 * IMPORTANT (read the top-level README): on x86_64 kernels 5.7+, syscalls
 * take a single `struct pt_regs *regs` argument, and the real syscall
 * arguments live INSIDE that pt_regs (regs->di, regs->si, ...), not in the
 * outer kprobe regs directly. This is the standard "ftrace-hook" pattern
 * used by most kernel security tooling on modern kernels.
 *
 * Build:   make
 * Load:    sudo insmod kprobe_log.ko
 * Trigger: run any command in another terminal, e.g. `ls`
 * Check:   dmesg | tail -20
 * Unload:  sudo rmmod kprobe_log
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

/* Adjust for your architecture if not x86_64 - see README. */
#define HOOKED_SYSCALL_NAME "__x64_sys_execve"

static struct kprobe kp = {
    .symbol_name = HOOKED_SYSCALL_NAME,
};

/*
 * Entry handler: fires before the real execve runs.
 * regs->di holds the syscall's pt_regs* (the "outer" kprobe arg on x86_64
 * syscall wrappers). The inner pt_regs->di is the actual first syscall
 * argument: const char __user *filename.
 */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = (struct pt_regs *)regs->di;
    const char __user *user_filename;
    char *kbuf;

    if (!real_regs)
        return 0;

    user_filename = (const char __user *)real_regs->di;
    if (!user_filename)
        return 0;

    kbuf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!kbuf)
        return 0;

    if (strncpy_from_user(kbuf, user_filename, PATH_MAX) > 0)
        pr_info("kernel-av/kprobe_log: execve(\"%s\") by pid %d (%s)\n",
                kbuf, current->pid, current->comm);

    kfree(kbuf);
    return 0; /* 0 = continue to the real syscall, unmodified */
}

static int __init kprobe_log_init(void)
{
    int ret;

    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("kernel-av/kprobe_log: register_kprobe failed: %d\n", ret);
        return ret;
    }

    pr_info("kernel-av/kprobe_log: hooked %s, watching execve calls\n",
            HOOKED_SYSCALL_NAME);
    return 0;
}

static void __exit kprobe_log_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("kernel-av/kprobe_log: unhooked, unloaded\n");
}

module_init(kprobe_log_init);
module_exit(kprobe_log_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Stage 0: kprobe execve logger (observe-only)");
MODULE_VERSION("0.1");
