/*
 * stage0/hello - the absolute minimum LKM.
 *
 * Goal: get comfortable with the module lifecycle and the build/insmod/
 * dmesg/rmmod workflow before touching anything that hooks the kernel.
 *
 * Build:   make
 * Load:    sudo insmod hello.ko
 * Check:   dmesg | tail
 * Unload:  sudo rmmod hello
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keane");
MODULE_DESCRIPTION("Stage 0: minimal LKM skeleton");
MODULE_VERSION("0.1");

static int __init hello_init(void)
{
    pr_info("kernel-av/hello: module loaded\n");
    return 0; /* 0 = success. Non-zero here means insmod fails. */
}

static void __exit hello_exit(void)
{
    pr_info("kernel-av/hello: module unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);
