/*
 * avctl - userspace CLI for /proc/kernel_av_signatures.
 *
 * Usage:
 *   avctl add <md5|sha1|sha256> <hex> <name>
 *   avctl del <md5|sha1|sha256> <hex>
 *   avctl list
 *
 * This is a plain userspace program (built with the host's regular gcc,
 * NOT the kernel headers/toolchain - see Makefile in this directory).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define PROC_PATH "/proc/kernel_av_signatures"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s add <md5|sha1|sha256> <hex> <name>\n"
        "  %s del <md5|sha1|sha256> <hex>\n"
        "  %s list\n",
        prog, prog, prog);
}

static int do_list(void)
{
    FILE *f = fopen(PROC_PATH, "r");
    char line[512];

    if (!f) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROC_PATH, strerror(errno));
        return 1;
    }

    printf("%-8s %-64s %s\n", "ALGO", "HASH", "NAME");
    while (fgets(line, sizeof(line), f)) {
        char algo[8], hex[65], name[128];
        if (sscanf(line, "%7s %64s %127[^\n]", algo, hex, name) == 3)
            printf("%-8s %-64s %s\n", algo, hex, name);
    }
    fclose(f);
    return 0;
}

static int write_command(const char *cmd)
{
    int fd = open(PROC_PATH, O_WRONLY);
    ssize_t written;

    if (fd < 0) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROC_PATH, strerror(errno));
        return 1;
    }

    written = write(fd, cmd, strlen(cmd));
    close(fd);

    if (written < 0) {
        fprintf(stderr, "avctl: write failed: %s\n"
                         "(need sudo? malformed hash/algo?)\n", strerror(errno));
        return 1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "list")) {
        return do_list();
    } else if (!strcmp(argv[1], "add")) {
        char cmd[256];

        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }
        snprintf(cmd, sizeof(cmd), "add %s %s %s", argv[2], argv[3], argv[4]);
        if (write_command(cmd))
            return 1;
        printf("added %s signature: %s (%s)\n", argv[2], argv[3], argv[4]);
    } else if (!strcmp(argv[1], "del")) {
        char cmd[256];

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        snprintf(cmd, sizeof(cmd), "del %s %s", argv[2], argv[3]);
        if (write_command(cmd))
            return 1;
        printf("removed %s signature: %s\n", argv[2], argv[3]);
    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}
