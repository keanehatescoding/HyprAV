/*
 * stage0/procfs_demo - a /proc entry you can read and write from userspace.
 *
 * This is the pattern you'll reuse constantly: it's how userspace will
 * later push signature hashes into the kernel (stage 2) and how the
 * kernel will report detections back out.
 *
 * Build:   make
 * Load:    sudo insmod procfs_demo.ko
 * Read:    cat /proc/kernel_av_demo
 * Write:   echo "hello" | sudo tee /proc/kernel_av_demo
 * Unload:  sudo rmmod procfs_demo
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROC_NAME "kernel_av_demo"
#define BUF_SIZE  256

static char message[BUF_SIZE] = "nothing written yet\n";
static struct proc_dir_entry *proc_entry;

static ssize_t demo_read(struct file *file, char __user *ubuf,
                          size_t count, loff_t *ppos)
{
    return simple_read_from_buffer(ubuf, count, ppos, message,
                                    strlen(message));
}

static ssize_t demo_write(struct file *file, const char __user *ubuf,
                           size_t count, loff_t *ppos)
{
    size_t len = min(count, (size_t)(BUF_SIZE - 1));

    if (copy_from_user(message, ubuf, len))
        return -EFAULT;

    message[len] = '\0';
    pr_info("kernel-av/procfs_demo: userspace wrote: %s\n", message);
    return count;
}

/* proc_ops replaced file_operations for /proc entries in kernel 5.6+ */
static const struct proc_ops demo_fops = {
    .proc_read  = demo_read,
    .proc_write = demo_write,
};

static int __init procfs_demo_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &demo_fops);
    if (!proc_entry) {
        pr_err("kernel-av/procfs_demo: failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    pr_info("kernel-av/procfs_demo: loaded, see /proc/%s\n", PROC_NAME);
    return 0;
}

static void __exit procfs_demo_exit(void)
{
    proc_remove(proc_entry);
    pr_info("kernel-av/procfs_demo: unloaded\n");
}

module_init(procfs_demo_init);
module_exit(procfs_demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Stage 0: /proc read/write demo");
MODULE_VERSION("0.1");
