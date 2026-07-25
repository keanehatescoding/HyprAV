/*
 * avd.c - userspace daemon: registers with the av kernel module over
 * Generic Netlink, receives scan requests, and replies with a verdict
 * based on YARA rule matching against the file at the given path.
 *
 * v0.3.0: real detection logic - loads all *.yar files from a rules
 * directory (default: ./rules, override with argv[1] or AVD_RULES_DIR)
 * at startup, then scans each requested file against them.
 *
 * Compile-verified against real libnl-genl-3.0 and libyara headers
 * (clean build, -Wall -Wextra, no warnings) and the rules in rules/
 * were verified to match with the real `yara` CLI. NOT yet
 * runtime-tested end-to-end against the actual kernel module together
 * with this - see docs/netlink-protocol.md and the top-level README's
 * netlink testing section.
 *
 * Dependencies (Arch/CachyOS):  sudo pacman -S libnl yara
 * Dependencies (Debian/Ubuntu): sudo apt install libnl-genl-3-dev libyara-dev
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

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <yara.h>

#include "../../av/netlink_proto.h"

#define DEFAULT_RULES_DIR "rules"
#define SCAN_TIMEOUT_SECS 10

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

struct yara_match_ctx {
    int matched;
    int match_count;
    char rule_name[AV_RULE_NAME_MAXLEN + 1]; /* comma-joined, truncated to fit */
};

static int yara_callback(YR_SCAN_CONTEXT *context, int message,
                          void *message_data, void *user_data)
{
    struct yara_match_ctx *ctx = (struct yara_match_ctx *)user_data;

    (void)context;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        size_t used = strlen(ctx->rule_name);
        size_t remaining = sizeof(ctx->rule_name) - used;

        ctx->matched = 1;
        ctx->match_count++;

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

static void handle_scan_request(uint64_t reqid, uint32_t pid,
                                 const char *path, const char *sha256_hex)
{
    struct yara_match_ctx ctx = { .matched = 0, .match_count = 0, .rule_name = "" };
    int ret;

    printf("avd: scan request reqid=%llu pid=%u path=\"%s\" sha256=%s\n",
           (unsigned long long)reqid, pid, path, sha256_hex);

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
        printf("avd: MATCH \"%s\" -> %d rule(s): \"%s\"\n",
               path, ctx.match_count, ctx.rule_name);
        send_verdict(reqid, AV_VERDICT_MALICIOUS, ctx.rule_name);
    } else {
        send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
    }
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

    if (argc > 1)
        rules_dir = argv[1];
    else if (getenv("AVD_RULES_DIR"))
        rules_dir = getenv("AVD_RULES_DIR");

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    if (load_rules(rules_dir) != 0) {
        fprintf(stderr, "avd: failed to initialize YARA - aborting\n");
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
    return 0;
}
