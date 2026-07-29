/*
 * avd.c - userspace daemon: registers with the av kernel module over
 * Generic Netlink, receives scan requests, and replies with a verdict
 * based on YARA rule matching and fuzzy-hash similarity against the
 * file at the given path.
 *
 * v0.3.0: netlink plumbing + YARA rule matching (rules directory)
 * v0.7.0: fuzzy hashing (ssdeep/libfuzzy) - runs when no YARA rule
 *         matched, comparing the file's fuzzy hash against a corpus
 *         of known-bad hashes (default: ./corpus/fuzzy_hashes.txt,
 *         override with argv[2] or AVD_CORPUS_FILE). Catches
 *         near-identical variants that would evade exact hash
 *         matching (av/sigtable.c) entirely - verified in this
 *         sandbox: a file with a few bytes appended scores 100
 *         similarity against the original, while an unrelated file
 *         scores 0.
 * v1.0.0-merge: quarantine (on any MALICIOUS verdict, the file is
 *         moved to /var/lib/av-quarantine/ and chmod 0000'd - see
 *         quarantine_file() below) and an `override` meta tier on top
 *         of the v0.9.1 scoring system - a small set of rules convict
 *         on their own regardless of aggregate score. Added after
 *         discovering the pure-additive scoring model let the
 *         v0.9.0 entropy-dilution evasion finding through the WHOLE
 *         pipeline once Entry_Point_Outside_Text's weight was reduced
 *         - see elf_analysis.yar and docs/evasion-findings.md.
 *         SCOPE LIMIT: quarantine only covers detections that go
 *         through avd (YARA, heuristics, fuzzy hash) - kernel-only
 *         detections (exact signature match, behavioral heuristics)
 *         still only kill, since file rename/unlink from KERNEL space
 *         needs vfs_rename()/vfs_unlink(), genuinely risky and
 *         version-fragile kernel API territory. Userspace rename()/
 *         chmod() has none of that risk.
 *
 * Compile-verified against real libnl-genl-3.0, libyara, and libfuzzy
 * headers (clean build, -Wall -Wextra, no warnings). The YARA rules
 * and fuzzy-hash comparison logic were verified against real samples
 * (see README testing sections for v0.3.0-v0.7.0) using the exact
 * scan/compare patterns used here. NOT yet runtime-tested end-to-end
 * against the actual kernel module together with this - see
 * docs/netlink-protocol.md and the top-level README's netlink testing
 * section.
 *
 * Dependencies (Arch/CachyOS):  sudo pacman -S libnl yara ssdeep
 * Dependencies (Debian/Ubuntu): sudo apt install libnl-genl-3-dev libyara-dev libfuzzy-dev
 *
 * See docs/netlink-protocol.md for the full protocol design.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <yara.h>
#include <fuzzy.h>

#include "../../av/netlink_proto.h"

#define DEFAULT_RULES_DIR      "rules"
#define DEFAULT_CORPUS_FILE    "corpus/fuzzy_hashes.txt"
#define DEFAULT_QUARANTINE_DIR "/var/lib/av-quarantine"
#define SCAN_TIMEOUT_SECS   10
#define MALICIOUS_SCORE_THRESHOLD 100
    /* Sum of every matching rule's `weight` meta (see the .yar files under rules/) has
     * to clear this before avd convicts. Added after real testing
     * killed /usr/bin/zsh, /bin/sh, and /usr/bin/uwsm - all legitimate
     * binaries that each matched exactly one low/medium-confidence
     * rule. Any single weak import heuristic (weight 5-15) or even a
     * "verified" structural rule alone (weight 30-55) now stays below
     * threshold; conviction requires corroboration across rules, which
     * is what the documented real UPX-packed test sample actually
     * produces (No_Section_Headers + Entry_Point_Outside_Text +
     * High_Overall_Entropy firing together comfortably clears this). */
#define FUZZY_MATCH_THRESHOLD 60 /* 0-100; see corpus/fuzzy_hashes.txt
                                   * and the README's v0.7.0 testing
                                   * section for how this was picked -
                                   * a starting point, not a final tuned
                                   * value, and worth revisiting once
                                   * you have a real sample corpus. */

struct fuzzy_corpus_entry {
    char hash[FUZZY_MAX_RESULT];
    char name[128];
};

static struct fuzzy_corpus_entry *fuzzy_corpus;
static size_t fuzzy_corpus_count;
static const char *quarantine_dir = DEFAULT_QUARANTINE_DIR;

static struct nl_sock *sock;
static int family_id;
static volatile sig_atomic_t running = 1;
static YR_RULES *compiled_rules;

static void handle_sigint(int signum)
{
    (void)signum;
    running = 0;
}

/*
 * Sends AV_C_VERDICT back to the kernel for the given request.
 * verdict: AV_VERDICT_CLEAN or AV_VERDICT_MALICIOUS.
 * rule_name: may be NULL/empty for a clean verdict.
 */
static int send_verdict(uint64_t reqid, uint8_t verdict, const char *rule_name)
{
    struct nl_msg *msg;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "avd: nlmsg_alloc failed\n");
        return -1;
    }

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                      AV_C_VERDICT, AV_GENL_VERSION)) {
        fprintf(stderr, "avd: genlmsg_put failed\n");
        nlmsg_free(msg);
        return -1;
    }

    NLA_PUT_U64(msg, AV_A_REQID, reqid);
    NLA_PUT_U8(msg, AV_A_VERDICT, verdict);
    if (rule_name && rule_name[0])
        NLA_PUT_STRING(msg, AV_A_RULE_NAME, rule_name);

    ret = nl_send_auto(sock, msg);
    nlmsg_free(msg);

    if (ret < 0) {
        fprintf(stderr, "avd: failed to send verdict: %s\n", nl_geterror(ret));
        return -1;
    }
    return 0;

nla_put_failure:
    fprintf(stderr, "avd: NLA_PUT failed building verdict message\n");
    nlmsg_free(msg);
    return -1;
}

/*
 * Loads every *.yar or *.yara file in `dir`, compiles them together, and
 * stores the result in compiled_rules. Continues past individual file
 * compile errors (reporting them) rather than failing the whole daemon
 * over one bad rule file - a malformed rule shouldn't take detection
 * offline entirely.
 */
static int load_rules(const char *dir)
{
    YR_COMPILER *compiler = NULL;
    DIR *d;
    struct dirent *entry;
    int loaded = 0;
    int total_errors = 0;

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "avd: yr_initialize failed\n");
        return -1;
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "avd: yr_compiler_create failed\n");
        yr_finalize();
        return -1;
    }

    d = opendir(dir);
    if (!d) {
        fprintf(stderr, "avd: could not open rules directory \"%s\": %s\n",
                dir, strerror(errno));
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    while ((entry = readdir(d)) != NULL) {
        char filepath[PATH_MAX];
        size_t len = strlen(entry->d_name);
        FILE *fp;
        int errors;
        bool is_yar = len >= 4 && !strcmp(entry->d_name + len - 4, ".yar");
        bool is_yara = len >= 5 && !strcmp(entry->d_name + len - 5, ".yara");

        if (!is_yar && !is_yara)
            continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", dir, entry->d_name);

        fp = fopen(filepath, "r");
        if (!fp) {
            fprintf(stderr, "avd: could not open rule file %s: %s\n",
                    filepath, strerror(errno));
            continue;
        }

        errors = yr_compiler_add_file(compiler, fp, NULL, filepath);
        fclose(fp);

        if (errors > 0) {
            fprintf(stderr, "avd: %d error(s) compiling %s - skipping\n",
                    errors, filepath);
            total_errors += errors;
        } else {
            printf("avd: loaded rules from %s\n", filepath);
            loaded++;
        }
    }
    closedir(d);

    if (loaded == 0)
        fprintf(stderr, "avd: no valid rule files loaded from \"%s\" - "
                        "all scans will report clean\n", dir);
    if (total_errors > 0)
        fprintf(stderr, "avd: %d total compile error(s) across all rule "
                        "files - continuing with whatever DID compile\n",
                total_errors);

    if (yr_compiler_get_rules(compiler, &compiled_rules) != ERROR_SUCCESS) {
        fprintf(stderr, "avd: yr_compiler_get_rules failed\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    yr_compiler_destroy(compiler); /* rules are now owned by compiled_rules */
    return 0;
}

/*
 * Loads the fuzzy-hash corpus from `path` (format: see
 * corpus/fuzzy_hashes.txt). Missing file or empty corpus is not fatal -
 * the daemon just won't have anything to fuzzy-match against, and logs
 * a warning once at startup rather than failing every scan silently.
 */
static int load_fuzzy_corpus(const char *path)
{
    FILE *fp;
    char line[512];
    size_t capacity = 16;

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "avd: could not open fuzzy corpus \"%s\": %s - "
                        "fuzzy matching disabled\n", path, strerror(errno));
        return 0; /* not fatal - YARA rules still work without this */
    }

    fuzzy_corpus = malloc(capacity * sizeof(*fuzzy_corpus));
    if (!fuzzy_corpus) {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *comma;
        char *newline;
        char *hash_part, *name_part;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
            continue;

        newline = strchr(line, '\n');
        if (newline)
            *newline = '\0';

        comma = strchr(line, ',');
        if (!comma) {
            fprintf(stderr, "avd: skipping malformed corpus line "
                            "(no comma): %s\n", line);
            continue;
        }
        *comma = '\0';
        hash_part = line;
        name_part = comma + 1;

        if (fuzzy_corpus_count == capacity) {
            struct fuzzy_corpus_entry *grown;

            capacity *= 2;
            grown = realloc(fuzzy_corpus, capacity * sizeof(*fuzzy_corpus));
            if (!grown) {
                fclose(fp);
                return -1;
            }
            fuzzy_corpus = grown;
        }

        snprintf(fuzzy_corpus[fuzzy_corpus_count].hash,
                 sizeof(fuzzy_corpus[fuzzy_corpus_count].hash),
                 "%.*s", (int)sizeof(fuzzy_corpus[fuzzy_corpus_count].hash) - 1,
                 hash_part);
        snprintf(fuzzy_corpus[fuzzy_corpus_count].name,
                 sizeof(fuzzy_corpus[fuzzy_corpus_count].name),
                 "%.*s", (int)sizeof(fuzzy_corpus[fuzzy_corpus_count].name) - 1,
                 name_part);
        fuzzy_corpus_count++;
    }
    fclose(fp);

    if (fuzzy_corpus_count == 0)
        fprintf(stderr, "avd: fuzzy corpus \"%s\" loaded but empty - "
                        "fuzzy matching will never trigger\n", path);
    else
        printf("avd: loaded %zu fuzzy hash(es) from %s\n",
               fuzzy_corpus_count, path);

    return 0;
}

/*
 * Compares the file at `path` against every entry in the fuzzy corpus.
 * On the best match at or above FUZZY_MATCH_THRESHOLD, copies the
 * corpus entry's name into name_out and the score into score_out,
 * returning 1. Returns 0 if nothing met the threshold (or no corpus
 * loaded), -1 on a hashing error (file vanished, unreadable, etc.).
 */
static int check_fuzzy_corpus(const char *path, char *name_out,
                               size_t name_out_len, int *score_out)
{
    char file_hash[FUZZY_MAX_RESULT];
    int best_score = -1;
    size_t best_idx = 0;
    size_t i;

    if (fuzzy_corpus_count == 0)
        return 0;

    if (fuzzy_hash_filename(path, file_hash) != 0)
        return -1;

    for (i = 0; i < fuzzy_corpus_count; i++) {
        int score = fuzzy_compare(file_hash, fuzzy_corpus[i].hash);

        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }

    if (best_score >= FUZZY_MATCH_THRESHOLD) {
        snprintf(name_out, name_out_len, "%s", fuzzy_corpus[best_idx].name);
        *score_out = best_score;
        return 1;
    }

    return 0;
}

struct yara_match_ctx {
    int matched;
    int match_count;
    int score; /* sum of every matched rule's `weight` meta - see
                * MALICIOUS_SCORE_THRESHOLD above */
    int override_matched; /* v1.0.0-merge: true if any matched rule
                            * carries `override = true` - convicts
                            * regardless of aggregate score. See
                            * elf_analysis.yar's header comment for
                            * why only a small, carefully-chosen set
                            * of rules get this. */
    char rule_name[AV_RULE_NAME_MAXLEN + 1]; /* comma-joined, truncated to fit */
};

static int yara_callback(YR_SCAN_CONTEXT *context, int message,
                          void *message_data, void *user_data)
{
    struct yara_match_ctx *ctx = (struct yara_match_ctx *)user_data;

    (void)context;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        YR_META *meta;
        size_t used = strlen(ctx->rule_name);
        size_t remaining = sizeof(ctx->rule_name) - used;

        ctx->matched = 1;
        ctx->match_count++;

        /* Every rule in the .yar files under rules/ carries a `weight` meta; a rule
         * missing one contributes 0 rather than crashing or silently
         * auto-convicting - fail toward "needs corroboration", not
         * toward "convict on anything". */
        yr_rule_metas_foreach(rule, meta) {
            if (meta->type == META_TYPE_INTEGER &&
                strcmp(meta->identifier, "weight") == 0) {
                ctx->score += (int)meta->integer;
            }
            if (meta->type == META_TYPE_BOOLEAN && meta->integer &&
                strcmp(meta->identifier, "override") == 0) {
                ctx->override_matched = 1;
            }
        }

        /* Collect every matching rule rather than stopping at the
         * first - with related rules (e.g. Imports_Ptrace and the
         * compound Multiple_Suspicious_Imports both matching the same
         * file), aborting early could hide the more meaningful
         * compound match behind a low-confidence single-API one. */
        if (remaining > 1) {
            snprintf(ctx->rule_name + used, remaining, "%s%s",
                     used > 0 ? "," : "", rule->identifier);
        }
        return CALLBACK_CONTINUE;
    }

    return CALLBACK_CONTINUE;
}

static int ensure_quarantine_dir(void)
{
    if (mkdir(quarantine_dir, 0700) == 0)
        return 0;
    if (errno == EEXIST)
        return 0;
    fprintf(stderr, "avd: could not create quarantine dir \"%s\": %s\n",
            quarantine_dir, strerror(errno));
    return -1;
}

/* Fallback for rename() failing with EXDEV (source and quarantine dir
 * on different filesystems/mounts) - plain copy, then unlink the
 * original. Not atomic like rename(), but correct. */
static int copy_and_unlink(const char *src, const char *dst)
{
    int in_fd, out_fd;
    char buf[65536];
    ssize_t n;
    int ret = 0;

    in_fd = open(src, O_RDONLY);
    if (in_fd < 0)
        return -1;

    out_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (out_fd < 0) {
        close(in_fd);
        return -1;
    }

    while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
        if (write(out_fd, buf, (size_t)n) != n) {
            ret = -1;
            break;
        }
    }
    if (n < 0)
        ret = -1;

    close(in_fd);
    close(out_fd);

    if (ret == 0 && unlink(src) != 0)
        ret = -1;
    if (ret != 0)
        unlink(dst); /* best-effort cleanup of the partial copy */

    return ret;
}

/*
 * Moves `path` into the quarantine directory and chmod's it to 0000
 * (unreadable/unwritable/unexecutable by anyone, including root
 * without an explicit chmod back - a deliberate speed bump against
 * accidental re-execution, not real access control). Logs the outcome
 * either way; a quarantine failure does NOT block the verdict already
 * being sent back to the kernel for the kill.
 *
 * `baseline`/`have_baseline`: identity of the file as captured by the
 * caller *before* the YARA/fuzzy scan ran (see handle_scan_request()).
 * `path` here is just a string, re-resolved by the kernel/libc at
 * rename() time - if something with write access to a directory in
 * that path swaps in a symlink between initial detection and this
 * call, a path-only rename() would happily quarantine (or in the
 * EXDEV fallback case, unlink()) whatever the attacker pointed it at
 * instead of the file that was actually scanned. Re-checking st_dev/
 * st_ino right before the rename can't close that window entirely
 * (there's still a much narrower gap between this check and the
 * rename() call itself, and a double-swap - back to the original
 * inode - would slip past an identity check alone), but it converts
 * an easy single-swap attack into a much harder timing race, which is
 * the same kind of risk-reduction-not-elimination tradeoff already
 * documented elsewhere in this codebase (see Has_RWX_Segment's scope
 * note). A more complete fix would scan and quarantine via an fd
 * opened once at the top of handle_scan_request() (rename() accepts
 * /proc/self/fd/N as a source, which resolves to the fd's dentry
 * directly rather than re-walking the path) - noted as a follow-up,
 * not done here since it also touches how YARA/fuzzy scanning read
 * the file, a larger change than this function alone.
 */
static void quarantine_file(const char *path, const struct stat *baseline,
                             bool have_baseline)
{
    char dest[PATH_MAX];
    const char *base;
    time_t now;

    if (ensure_quarantine_dir() != 0)
        return;

    if (have_baseline) {
        struct stat now_st;

        if (lstat(path, &now_st) != 0) {
            fprintf(stderr, "avd: refusing to quarantine \"%s\": lstat "
                            "failed at quarantine time: %s\n",
                            path, strerror(errno));
            return;
        }
        if (now_st.st_dev != baseline->st_dev ||
            now_st.st_ino != baseline->st_ino) {
            fprintf(stderr, "avd: refusing to quarantine \"%s\": path now "
                            "resolves to a different file than the one "
                            "scanned (dev/ino changed) - possible symlink "
                            "swap\n", path);
            return;
        }
    }

    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    now = time(NULL);

    snprintf(dest, sizeof(dest), "%s/%ld_%s.quarantined",
             quarantine_dir, (long)now, base);

    if (rename(path, dest) != 0) {
        if (errno == EXDEV) {
            if (copy_and_unlink(path, dest) != 0) {
                fprintf(stderr, "avd: quarantine copy fallback failed for "
                                "\"%s\": %s\n", path, strerror(errno));
                return;
            }
        } else {
            fprintf(stderr, "avd: quarantine rename failed for \"%s\": %s\n",
                    path, strerror(errno));
            return;
        }
    }

    if (chmod(dest, 0000) != 0)
        fprintf(stderr, "avd: quarantined \"%s\" to \"%s\" but chmod failed: "
                        "%s\n", path, dest, strerror(errno));
    else
        printf("avd: QUARANTINED \"%s\" -> \"%s\"\n", path, dest);
}

static void handle_scan_request(uint64_t reqid, uint32_t pid,
                                 const char *path, const char *sha256_hex)
{
    struct yara_match_ctx ctx = { .matched = 0, .match_count = 0, .score = 0,
                                   .override_matched = 0, .rule_name = "" };
    struct stat baseline_st;
    bool have_baseline;
    int ret;

    printf("avd: scan request reqid=%llu pid=%u path=\"%s\" sha256=%s\n",
           (unsigned long long)reqid, pid, path, sha256_hex);

    /* Captured before the scan runs (which can itself take up to
     * SCAN_TIMEOUT_SECS) so the quarantine-time check below covers as
     * much of the window as possible - see quarantine_file()'s comment
     * for what this can and can't protect against. A failed lstat here
     * just means quarantine_file() skips the identity check later
     * (fail-open on the check itself, matching this codebase's existing
     * stance on inconclusive information elsewhere) rather than
     * blocking the scan. */
    have_baseline = (lstat(path, &baseline_st) == 0);

    if (!compiled_rules) {
        send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
        return;
    }

    ret = yr_rules_scan_file(compiled_rules, path, 0, yara_callback, &ctx,
                              SCAN_TIMEOUT_SECS);
    if (ret != ERROR_SUCCESS) {
        /* File vanished, permission denied, scan timeout, etc. - fail
         * open here too, matching the kernel side's own fail-open
         * stance on inconclusive information (see docs/netlink-protocol.md). */
        fprintf(stderr, "avd: yr_rules_scan_file(\"%s\") failed: error %d\n",
                path, ret);
        send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
        return;
    }

    if (ctx.matched) {
        /* Sum of matched rules' weights has to clear
         * MALICIOUS_SCORE_THRESHOLD before this convicts - a single
         * low-confidence import heuristic (or even one "verified"
         * structural rule alone) is logged for visibility but no
         * longer enough by itself. See the threshold's own comment
         * for why: real testing killed zsh/sh/uwsm on exactly this
         * single-weak-match pattern before this existed.
         *
         * EXCEPT: a small, deliberately narrow set of rules carry
         * `override = true` and convict on their own regardless of
         * score - added after discovering that pure additive scoring
         * let the v0.9.0 entropy-dilution evasion through the WHOLE
         * pipeline (not just the entropy layer) once Entry_Point_
         * Outside_Text's weight was reduced for its own false
         * positive. See elf_analysis.yar's header comment and
         * docs/evasion-findings.md for the full story. */
        if (ctx.override_matched || ctx.score >= MALICIOUS_SCORE_THRESHOLD) {
            printf("avd: MATCH \"%s\" -> %d rule(s), score=%d, override=%d: \"%s\"\n",
                   path, ctx.match_count, ctx.score, ctx.override_matched,
                   ctx.rule_name);
            quarantine_file(path, &baseline_st, have_baseline);
            send_verdict(reqid, AV_VERDICT_MALICIOUS, ctx.rule_name);
            return;
        }

        printf("avd: %d rule(s) matched \"%s\" but score=%d is below "
               "threshold (%d) and no override rule fired - not "
               "convicting: \"%s\"\n",
               ctx.match_count, path, ctx.score,
               MALICIOUS_SCORE_THRESHOLD, ctx.rule_name);
        /* Falls through to the fuzzy-hash check below rather than
         * returning CLEAN immediately - a below-threshold YARA match
         * plus a fuzzy-hash hit against the known-bad corpus is still
         * worth convicting on, even though neither alone was enough. */
    }

    /* No YARA rule fired - try fuzzy-hash similarity against the
     * corpus before declaring clean. This catches near-identical
     * variants of a known-bad file that would evade both the kernel's
     * exact hash check (av/sigtable.c) and exact YARA string/structure
     * matches. */
    {
        char fuzzy_name[128];
        int fuzzy_score = 0;
        int fret = check_fuzzy_corpus(path, fuzzy_name, sizeof(fuzzy_name),
                                       &fuzzy_score);

        if (fret == 1) {
            char verdict_name[AV_RULE_NAME_MAXLEN + 1];

            /* fuzzy_compare()'s documented range is 0-100; clamping
             * here (defensive, should never actually trigger) also
             * gives the compiler's range analysis what it needs to
             * prove the snprintf below can't truncate. */
            if (fuzzy_score < 0)
                fuzzy_score = 0;
            if (fuzzy_score > 100)
                fuzzy_score = 100;

            snprintf(verdict_name, sizeof(verdict_name),
                     "Fuzzy:%.40s(%d)", fuzzy_name, fuzzy_score);
            printf("avd: FUZZY MATCH \"%s\" -> \"%s\" score=%d\n",
                   path, fuzzy_name, fuzzy_score);
            quarantine_file(path, &baseline_st, have_baseline);
            send_verdict(reqid, AV_VERDICT_MALICIOUS, verdict_name);
            return;
        }
        if (fret < 0)
            fprintf(stderr, "avd: fuzzy hash of \"%s\" failed\n", path);
    }

    send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
}

static struct nla_policy av_policy[AV_A_MAX + 1] = {
    [AV_A_REQID]  = { .type = NLA_U64 },
    [AV_A_PID]    = { .type = NLA_U32 },
    [AV_A_PATH]   = { .type = NLA_STRING },
    [AV_A_SHA256] = { .type = NLA_STRING },
};

static int msg_handler(struct nl_msg *msg, void *arg)
{
    (void)arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);
    struct nlattr *attrs[AV_A_MAX + 1];

    if (genlmsg_parse(nlh, 0, attrs, AV_A_MAX, av_policy) < 0) {
        fprintf(stderr, "avd: failed to parse incoming message\n");
        return NL_SKIP;
    }

    if (gnlh->cmd == AV_C_SCAN_REQUEST) {
        if (!attrs[AV_A_REQID] || !attrs[AV_A_PATH]) {
            fprintf(stderr, "avd: malformed SCAN_REQUEST (missing attrs)\n");
            return NL_SKIP;
        }
        handle_scan_request(
            nla_get_u64(attrs[AV_A_REQID]),
            attrs[AV_A_PID] ? nla_get_u32(attrs[AV_A_PID]) : 0,
            nla_get_string(attrs[AV_A_PATH]),
            attrs[AV_A_SHA256] ? nla_get_string(attrs[AV_A_SHA256]) : "");
    }

    return NL_OK;
}

static int register_with_kernel(void)
{
    struct nl_msg *msg;
    int ret;

    msg = nlmsg_alloc();
    if (!msg)
        return -1;

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                      AV_C_REGISTER, AV_GENL_VERSION)) {
        nlmsg_free(msg);
        return -1;
    }

    ret = nl_send_auto(sock, msg);
    nlmsg_free(msg);
    return ret < 0 ? -1 : 0;
}

int main(int argc, char **argv)
{
    const char *rules_dir = DEFAULT_RULES_DIR;
    const char *corpus_file = DEFAULT_CORPUS_FILE;

    if (argc > 1)
        rules_dir = argv[1];
    else if (getenv("AVD_RULES_DIR"))
        rules_dir = getenv("AVD_RULES_DIR");

    if (argc > 2)
        corpus_file = argv[2];
    else if (getenv("AVD_CORPUS_FILE"))
        corpus_file = getenv("AVD_CORPUS_FILE");

    if (argc > 3)
        quarantine_dir = argv[3];
    else if (getenv("AVD_QUARANTINE_DIR"))
        quarantine_dir = getenv("AVD_QUARANTINE_DIR");

    printf("avd: quarantine directory: %s\n", quarantine_dir);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    if (load_rules(rules_dir) != 0) {
        fprintf(stderr, "avd: failed to initialize YARA - aborting\n");
        return 1;
    }

    if (load_fuzzy_corpus(corpus_file) != 0) {
        fprintf(stderr, "avd: failed to initialize fuzzy corpus - aborting\n");
        return 1;
    }

    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "avd: nl_socket_alloc failed\n");
        return 1;
    }

    /* We receive kernel-INITIATED messages (SCAN_REQUEST), which don't
     * carry a sequence number libnl is expecting a reply to - without
     * this, libnl silently drops them as "sequence mismatch". */
    nl_socket_disable_seq_check(sock);
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, msg_handler, NULL);

    if (genl_connect(sock) < 0) {
        fprintf(stderr, "avd: genl_connect failed - is the av module loaded?\n");
        nl_socket_free(sock);
        return 1;
    }

    family_id = genl_ctrl_resolve(sock, AV_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "avd: could not resolve family \"%s\" - "
                        "is the av module loaded? (sudo insmod av/av.ko)\n",
                AV_GENL_FAMILY_NAME);
        nl_socket_free(sock);
        return 1;
    }

    if (register_with_kernel() < 0) {
        fprintf(stderr, "avd: failed to register with kernel module\n");
        nl_socket_free(sock);
        return 1;
    }

    printf("avd: registered with kernel module (family id %d), listening...\n",
           family_id);

    while (running) {
        int ret = nl_recvmsgs_default(sock);
        if (ret < 0 && ret != -NLE_INTR) {
            fprintf(stderr, "avd: nl_recvmsgs_default error: %s\n",
                    nl_geterror(ret));
            break;
        }
    }

    printf("avd: shutting down\n");
    nl_socket_free(sock);
    if (compiled_rules)
        yr_rules_destroy(compiled_rules);
    yr_finalize();
    free(fuzzy_corpus);
    return 0;
}
