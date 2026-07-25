/*
 * avd.c - userspace daemon: registers with the av kernel module over
 * Generic Netlink, receives scan requests, and replies with a verdict.
 *
 * STUB WARNING: this currently always replies "clean" - it's the
 * plumbing for v0.3.0 (YARA), not the feature itself. Real detection
 * logic (libyara integration) goes in handle_scan_request() below.
 *
 * Compile-verified against real libnl-genl-3.0 headers (clean build,
 * -Wall -Wextra, no warnings). NOT yet runtime-tested against the
 * actual kernel module - the netlink_chan.c kernel side is unverified
 * against real kernel headers (see its own UNTESTED note), so the
 * first real test of this whole path happens together in your VM.
 *
 * Dependencies (Arch/CachyOS):  sudo pacman -S libnl
 * Dependencies (Debian/Ubuntu): sudo apt install libnl-genl-3-dev
 *
 * See docs/netlink-protocol.md for the full protocol design.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "../../av/netlink_proto.h"

static struct nl_sock *sock;
static int family_id;
static volatile sig_atomic_t running = 1;

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
 * STUB: this is where v0.3.0's actual detection logic goes (libyara
 * against the file at `path`, using `sha256_hex` for caching/logging).
 * For now: always clean, so the plumbing is testable end to end before
 * real detection logic is added.
 */
static void handle_scan_request(uint64_t reqid, uint32_t pid,
                                 const char *path, const char *sha256_hex)
{
    printf("avd: scan request reqid=%llu pid=%u path=\"%s\" sha256=%s\n",
           (unsigned long long)reqid, pid, path, sha256_hex);

    /* TODO (v0.3.0): run YARA rules against `path`, and reply
     * AV_VERDICT_MALICIOUS with the matched rule name if something hits. */
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

int main(void)
{
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

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
    return 0;
}
