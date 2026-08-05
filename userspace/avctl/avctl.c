/*
 * avctl - userspace CLI for /proc/kernel_av_signatures and
 * /proc/kernel_av_trusted.
 *
 * Usage:
 *   avctl add <md5|sha1|sha256> <hex> <name>
 *   avctl del <md5|sha1|sha256> <hex>
 *   avctl list
 *   avctl trust add <sha256-hex> <name>
 *   avctl trust del <sha256-hex>
 *   avctl trust list
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
#define TRUST_PROC_PATH "/proc/kernel_av_trusted"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s add <md5|sha1|sha256> <hex> <name>\n"
        "  %s del <md5|sha1|sha256> <hex>\n"
        "  %s list\n"
        "  %s trust add <sha256-hex> <name>\n"
        "  %s trust del <sha256-hex>\n"
        "  %s trust list\n",
        prog, prog, prog, prog, prog, prog);
}

static int do_list_generic(const char *path, const char *header_algo)
{
    FILE *f = fopen(path, "r");
    char line[512];

    if (!f) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                path, strerror(errno));
        return 1;
    }

    if (header_algo) {
        printf("%-8s %-64s %s\n", header_algo, "HASH", "NAME");
        while (fgets(line, sizeof(line), f)) {
            char algo[8], hex[65], name[128];
            if (sscanf(line, "%7s %64s %127[^\n]", algo, hex, name) == 3)
                printf("%-8s %-64s %s\n", algo, hex, name);
        }
    } else {
        printf("%-64s %s\n", "SHA256", "NAME");
        while (fgets(line, sizeof(line), f)) {
            char hex[65], name[128];
            if (sscanf(line, "%64s %127[^\n]", hex, name) == 2)
                printf("%-64s %s\n", hex, name);
        }
    }
    fclose(f);
    return 0;
}

static int do_list(void)
{
    return do_list_generic(PROC_PATH, "ALGO");
}

static int do_trust_list(void)
{
    return do_list_generic(TRUST_PROC_PATH, NULL);
}

static int write_command_to(const char *path, const char *cmd)
{
    int fd = open(path, O_WRONLY);
    ssize_t written;

    if (fd < 0) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                path, strerror(errno));
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

static int write_command(const char *cmd)
{
    return write_command_to(PROC_PATH, cmd);
}

static int do_trust(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[2], "list")) {
        return do_trust_list();
    } else if (!strcmp(argv[2], "add")) {
        char cmd[256];

        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }
        snprintf(cmd, sizeof(cmd), "add %s %s", argv[3], argv[4]);
        if (write_command_to(TRUST_PROC_PATH, cmd))
            return 1;
        printf("trusted: %s (%s)\n", argv[3], argv[4]);
    } else if (!strcmp(argv[2], "del")) {
        char cmd[256];

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        snprintf(cmd, sizeof(cmd), "del %s", argv[3]);
        if (write_command_to(TRUST_PROC_PATH, cmd))
            return 1;
        printf("untrusted: %s\n", argv[3]);
    } else {
        usage(argv[0]);
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
    } else if (!strcmp(argv[1], "trust")) {
        return do_trust(argc, argv);
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
