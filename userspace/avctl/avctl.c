/*
 * avctl - userspace CLI for /proc/kernel_av_signatures,
 * /proc/kernel_av_trusted, and /proc/kernel_av_protected.
 *
 * Usage:
 *   avctl add <md5|sha1|sha256> <hex> <name>
 *   avctl del <md5|sha1|sha256> <hex>
 *   avctl list
 *   avctl trust add <sha256-hex> <name>
 *   avctl trust del <sha256-hex>
 *   avctl trust list
 *   avctl protect add <absolute-path>
 *   avctl protect del <absolute-path>
 *   avctl protect list
 *   avctl save <file>
 *   avctl load <file>
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
#include <limits.h>

#define PROC_PATH "/proc/kernel_av_signatures"
#define TRUST_PROC_PATH "/proc/kernel_av_trusted"
#define PROTECTED_PROC_PATH "/proc/kernel_av_protected"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s add <md5|sha1|sha256> <hex> <name>\n"
        "  %s del <md5|sha1|sha256> <hex>\n"
        "  %s list\n"
        "  %s trust add <sha256-hex> <name>\n"
        "  %s trust del <sha256-hex>\n"
        "  %s trust list\n"
        "  %s protect add <absolute-path>\n"
        "  %s protect del <absolute-path>\n"
        "  %s protect list\n"
        "  %s save <file>\n"
        "  %s load <file>\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
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

/* Not do_list_generic(): the protected-path list is one path per
 * line, not hash/name pairs. */
static int do_protect_list(void)
{
    FILE *f = fopen(PROTECTED_PROC_PATH, "r");
    char line[PATH_MAX + 8];

    if (!f) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROTECTED_PROC_PATH, strerror(errno));
        return 1;
    }

    printf("PROTECTED PATH\n");
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (line[0])
            printf("%s\n", line);
    }
    fclose(f);
    return 0;
}

static int write_command_to(const char *path, const char *cmd)
{
    int fd = open(path, O_WRONLY);
    ssize_t written;
    int saved_errno;
    size_t cmd_len;
    char *buf;

    if (fd < 0) {
        saved_errno = errno;
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                path, strerror(saved_errno));
        return -saved_errno;
    }

    /* Kernel-side proc write handlers require a trailing newline as an
     * explicit "this is a complete, non-truncated command" marker (see
     * protected_proc_write()'s comment in av/behavior.c) - build ONE
     * buffer with it appended and issue a SINGLE write() for the
     * whole thing, rather than a second write() call for just "\n"
     * afterward, which would itself land at a nonzero file offset and
     * get rejected as an unexpected continuation of the first. */
    cmd_len = strlen(cmd);
    buf = malloc(cmd_len + 2);
    if (!buf) {
        close(fd);
        fprintf(stderr, "avctl: out of memory\n");
        return -ENOMEM;
    }
    memcpy(buf, cmd, cmd_len);
    buf[cmd_len] = '\n';
    buf[cmd_len + 1] = '\0';

    written = write(fd, buf, cmd_len + 1);
    saved_errno = errno; /* capture before close()/free() can touch it */
    free(buf);
    close(fd);

    if (written < 0) {
        fprintf(stderr, "avctl: write failed: %s\n"
                         "(need sudo? malformed hash/algo?)\n", strerror(saved_errno));
        return -saved_errno;
    }

    return 0;
}

static int write_command(const char *cmd)
{
    return write_command_to(PROC_PATH, cmd);
}

/* save/load: /proc/kernel_av_signatures and /proc/kernel_av_trusted are
 * both in-memory kernel hashtables with no persistence of their own -
 * everything vanishes on `rmmod`. save dumps all three into one file as
 * replayable write-commands (not the pretty-printed list() format);
 * load replays them. A "sig ", "trust ", or "protect " line prefix says
 * which /proc file each line targets; the rest of the line is passed
 * through VERBATIM as the write() payload, so names/paths containing
 * spaces round-trip correctly (the underlying /proc write handlers
 * already treat everything after the hash/command as the rest-of-line
 * value - see sig_proc_write()/trust_proc_write()/protected_proc_write()
 * in the kernel module). Line buffer sized for PATH_MAX (protected-path
 * entries can be much longer than a sha256 signature/name line). */
static int do_save(const char *path)
{
    FILE *out;
    FILE *in;
    char line[PATH_MAX + 16];
    int sig_count = 0, trust_count = 0, protect_count = 0;

    out = fopen(path, "w");
    if (!out) {
        fprintf(stderr, "avctl: could not open %s for writing: %s\n",
                path, strerror(errno));
        return 1;
    }

    fprintf(out, "# kernel-av state dump - replay with: avctl load %s\n", path);

    in = fopen(PROC_PATH, "r");
    if (!in) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROC_PATH, strerror(errno));
        fclose(out);
        return 1;
    }
    while (fgets(line, sizeof(line), in)) {
        char algo[8], hex[65], name[128];

        if (sscanf(line, "%7s %64s %127[^\n]", algo, hex, name) == 3) {
            fprintf(out, "sig add %s %s %s\n", algo, hex, name);
            sig_count++;
        }
    }
    fclose(in);

    in = fopen(TRUST_PROC_PATH, "r");
    if (!in) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                TRUST_PROC_PATH, strerror(errno));
        fclose(out);
        return 1;
    }
    while (fgets(line, sizeof(line), in)) {
        char hex[65], name[128];

        if (sscanf(line, "%64s %127[^\n]", hex, name) == 2) {
            fprintf(out, "trust add %s %s\n", hex, name);
            trust_count++;
        }
    }
    fclose(in);

    in = fopen(PROTECTED_PROC_PATH, "r");
    if (!in) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROTECTED_PROC_PATH, strerror(errno));
        fclose(out);
        return 1;
    }
    while (fgets(line, sizeof(line), in)) {
        size_t len = strlen(line);

        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (line[0]) {
            fprintf(out, "protect add %s\n", line);
            protect_count++;
        }
    }
    fclose(in);

    fclose(out);
    printf("saved %d signature(s), %d trusted entr%s, %d protected path%s to %s\n",
           sig_count, trust_count, trust_count == 1 ? "y" : "ies",
           protect_count, protect_count == 1 ? "" : "s", path);
    return 0;
}

static int do_load(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[PATH_MAX + 16];
    int loaded = 0, skipped = 0, errors = 0;

    if (!f) {
        fprintf(stderr, "avctl: could not open %s: %s\n", path, strerror(errno));
        return 1;
    }

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        const char *rest;
        int ret;

        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (!strncmp(line, "sig ", 4)) {
            rest = line + 4;
            ret = write_command(rest);
        } else if (!strncmp(line, "trust ", 6)) {
            rest = line + 6;
            ret = write_command_to(TRUST_PROC_PATH, rest);
        } else if (!strncmp(line, "protect ", 8)) {
            rest = line + 8;
            ret = write_command_to(PROTECTED_PROC_PATH, rest);
        } else {
            fprintf(stderr, "avctl: load: malformed line (expected "
                             "'sig ', 'trust ', or 'protect ' prefix): %s\n",
                    line);
            errors++;
            continue;
        }

        if (ret == -EEXIST) {
            /* Expected on a re-load: the module always seeds the
             * default EICAR test signature at insmod time, so
             * replaying a save file taken after that seed will hit
             * this for that one entry specifically. Not a failure. */
            printf("already present, skipping: %s\n", rest);
            skipped++;
        } else if (ret) {
            fprintf(stderr, "avctl: load: failed on line: %s\n", line);
            errors++;
        } else {
            loaded++;
        }
    }
    fclose(f);

    printf("loaded %d, skipped %d (already present), %d error%s\n",
           loaded, skipped, errors, errors == 1 ? "" : "s");

    return errors ? 1 : 0;
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
        char name[192];
        size_t off = 0;
        int i;

        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }

        /* Join every remaining argv[] into one space-separated name
         * instead of using only argv[4] - the kernel side's
         * trust_proc_write() already parses the rest of the line as
         * the name via "%63[^\n]" (save/load round-trip multi-word
         * names fine through that same path), so an unquoted
         * multi-word name like `avctl trust add <hash> My Program`
         * was silently losing everything after the first word only
         * because avctl itself dropped it before it ever reached the
         * kernel. */
        name[0] = '\0';
        for (i = 4; i < argc && off < sizeof(name) - 1; i++) {
            int n = snprintf(name + off, sizeof(name) - off, "%s%s",
                              i > 4 ? " " : "", argv[i]);
            if (n < 0)
                break;
            off += (size_t)n;
        }

        snprintf(cmd, sizeof(cmd), "add %s %s", argv[3], name);
        if (write_command_to(TRUST_PROC_PATH, cmd))
            return 1;
        printf("trusted: %s (%s)\n", argv[3], name);
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

static int do_protect(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[2], "list")) {
        return do_protect_list();
    } else if (!strcmp(argv[2], "add")) {
        char cmd[PATH_MAX + 8];
        int n;

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (argv[3][0] != '/') {
            fprintf(stderr, "avctl: protect add requires an absolute path\n");
            return 1;
        }
        /* Reject up front rather than letting snprintf() silently
         * truncate: a truncated write would ask the kernel side to
         * protect/unprotect a DIFFERENT (shorter) path than the one
         * printed back to the caller, with no error either side. */
        if (strlen(argv[3]) >= PATH_MAX) {
            fprintf(stderr, "avctl: path too long (max %d bytes)\n", PATH_MAX - 1);
            return 1;
        }
        n = snprintf(cmd, sizeof(cmd), "add %s", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: path too long to format\n");
            return 1;
        }
        if (write_command_to(PROTECTED_PROC_PATH, cmd))
            return 1;
        printf("protected: %s\n", argv[3]);
    } else if (!strcmp(argv[2], "del")) {
        char cmd[PATH_MAX + 8];
        int n;

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (strlen(argv[3]) >= PATH_MAX) {
            fprintf(stderr, "avctl: path too long (max %d bytes)\n", PATH_MAX - 1);
            return 1;
        }
        n = snprintf(cmd, sizeof(cmd), "del %s", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: path too long to format\n");
            return 1;
        }
        if (write_command_to(PROTECTED_PROC_PATH, cmd))
            return 1;
        printf("unprotected: %s\n", argv[3]);
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
    } else if (!strcmp(argv[1], "protect")) {
        return do_protect(argc, argv);
    } else if (!strcmp(argv[1], "save")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        return do_save(argv[2]);
    } else if (!strcmp(argv[1], "load")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        return do_load(argv[2]);
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
