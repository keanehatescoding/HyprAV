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
 * Dependencies (Debian/Ubuntu): sudo apt install libnl-genl-3-dev libyara-dev
 * libfuzzy-dev
 *
 * See docs/netlink-protocol.md for the full protocol design.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <fuzzy.h>
#include <yara.h>

#include "../../av/netlink_proto.h"

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000 /* glibc's plain <fcntl.h> doesn't define this
                              * (only <linux/fcntl.h> does, which risks
                              * conflicting struct/macro redefinitions if
                              * included alongside <fcntl.h> on some glibc
                              * versions) - the value itself is kernel UAPI,
                              * ABI-stable, safe to hardcode. Used by
                              * quarantine_file()'s linkat() call below. */
#endif

#define DEFAULT_RULES_DIR "rules"
#define DEFAULT_CORPUS_FILE "corpus/fuzzy_hashes.txt"
#define DEFAULT_QUARANTINE_DIR "/var/lib/av-quarantine"
#define SCAN_TIMEOUT_SECS 10
#define MALICIOUS_SCORE_THRESHOLD 100
/* handle_scan_request() (YARA scan, up to SCAN_TIMEOUT_SECS, plus the
 * fuzzy-hash pass) used to run synchronously inside msg_handler(),
 * called directly from the single nl_recvmsgs_default() loop in
 * main(). A second SCAN_REQUEST arriving while a scan was in
 * progress got no verdict at all until the first one finished - the
 * kernel side's own DAEMON_TIMEOUT_MS would then fire and fail open,
 * so any burst of concurrent execs (or an attacker deliberately
 * racing many at once) silently dropped detection to zero for
 * everything but the first. Fixed by moving the scan itself onto a
 * fixed-size worker pool (AVD_SCAN_THREADS) fed by a bounded queue
 * (AVD_SCAN_QUEUE_MAX) - msg_handler() now only copies the request
 * and enqueues it, keeping the netlink recv loop free to keep
 * accepting new requests while scans run in parallel. */
#define AVD_SCAN_THREADS 8
#define AVD_SCAN_QUEUE_MAX 256
/* Sum of every matching rule's `weight` meta (see the .yar files under rules/)
 * has to clear this before avd convicts. Added after real testing killed
 * /usr/bin/zsh, /bin/sh, and /usr/bin/uwsm - all legitimate binaries that each
 * matched exactly one low/medium-confidence rule. Any single weak import
 * heuristic (weight 5-15) or even a "verified" structural rule alone (weight
 * 30-55) now stays below threshold; conviction requires corroboration across
 * rules, which is what the documented real UPX-packed test sample actually
 * produces (No_Section_Headers + Entry_Point_Outside_Text +
 * High_Overall_Entropy firing together comfortably clears this). */
#define FUZZY_MATCH_THRESHOLD                                                  \
  60 /* 0-100; see corpus/fuzzy_hashes.txt                                     \
      * and the README's v0.7.0 testing                                        \
      * section for how this was picked -                                      \
      * a starting point, not a final tuned                                    \
      * value, and worth revisiting once                                       \
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

/* nl_send_auto() touches `sock`'s internal sequence-number/port state,
 * which libnl does not guarantee is safe for concurrent callers - so
 * every send_verdict() call (now potentially from any of the
 * AVD_SCAN_THREADS worker threads) takes this around the actual send.
 * Held only around message construction+send, never around the scan
 * itself, so contention is negligible. compiled_rules and
 * fuzzy_corpus need no such lock: both are populated once at startup
 * (load_rules()/load_fuzzy_corpus()) before any worker thread exists
 * and are read-only from then on - yr_rules_scan_fd() (or
 * yr_rules_scan_file()) against a shared, unmodified YR_RULES is
 * documented as safe for concurrent callers on that basis. */
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;

/* Bounded producer/consumer queue between msg_handler() (the single
 * netlink recv thread - producer) and the AVD_SCAN_THREADS scan
 * workers (consumers). A linked list rather than a ring buffer since
 * depth is small and this isn't a hot path relative to the scan
 * itself. `shutting_down` lets both a full queue's producer-side wait
 * and an empty queue's consumer-side wait unblock cleanly on
 * SIGINT/SIGTERM instead of hanging the process past `running = 0`. */
struct scan_task {
  struct scan_task *next;
  uint64_t reqid;
  uint32_t pid;
  char path[PATH_MAX];
  char sha256_hex[65];
};

static struct scan_task *queue_head, *queue_tail;
static size_t queue_len;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t queue_not_full = PTHREAD_COND_INITIALIZER;
static bool shutting_down;

static void handle_sigint(int signum) {
  (void)signum;
  running = 0;
}

/*
 * Sends AV_C_VERDICT back to the kernel for the given request.
 * verdict: AV_VERDICT_CLEAN or AV_VERDICT_MALICIOUS.
 * rule_name: may be NULL/empty for a clean verdict.
 */
static int send_verdict(uint64_t reqid, uint8_t verdict,
                        const char *rule_name) {
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

  pthread_mutex_lock(&send_lock);
  ret = nl_send_auto(sock, msg);
  pthread_mutex_unlock(&send_lock);
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
static int load_rules(const char *dir) {
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
    fprintf(stderr, "avd: could not open rules directory \"%s\": %s\n", dir,
            strerror(errno));
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
      fprintf(stderr, "avd: could not open rule file %s: %s\n", filepath,
              strerror(errno));
      continue;
    }

    errors = yr_compiler_add_file(compiler, fp, NULL, filepath);
    fclose(fp);

    if (errors > 0) {
      fprintf(stderr, "avd: %d error(s) compiling %s - skipping\n", errors,
              filepath);
      total_errors += errors;
    } else {
      printf("avd: loaded rules from %s\n", filepath);
      loaded++;
    }
  }
  closedir(d);

  if (loaded == 0)
    fprintf(stderr,
            "avd: no valid rule files loaded from \"%s\" - "
            "all scans will report clean\n",
            dir);
  if (total_errors > 0)
    fprintf(stderr,
            "avd: %d total compile error(s) across all rule "
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
static int load_fuzzy_corpus(const char *path) {
  FILE *fp;
  char line[512];
  size_t capacity = 16;

  fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr,
            "avd: could not open fuzzy corpus \"%s\": %s - "
            "fuzzy matching disabled\n",
            path, strerror(errno));
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
      fprintf(stderr,
              "avd: skipping malformed corpus line "
              "(no comma): %s\n",
              line);
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
             sizeof(fuzzy_corpus[fuzzy_corpus_count].hash), "%.*s",
             (int)sizeof(fuzzy_corpus[fuzzy_corpus_count].hash) - 1, hash_part);
    snprintf(fuzzy_corpus[fuzzy_corpus_count].name,
             sizeof(fuzzy_corpus[fuzzy_corpus_count].name), "%.*s",
             (int)sizeof(fuzzy_corpus[fuzzy_corpus_count].name) - 1, name_part);
    fuzzy_corpus_count++;
  }
  fclose(fp);

  if (fuzzy_corpus_count == 0)
    fprintf(stderr,
            "avd: fuzzy corpus \"%s\" loaded but empty - "
            "fuzzy matching will never trigger\n",
            path);
  else
    printf("avd: loaded %zu fuzzy hash(es) from %s\n", fuzzy_corpus_count,
           path);

  return 0;
}

/*
 * Compares the already-open file `fd` against every entry in the
 * fuzzy corpus. On the best match at or above FUZZY_MATCH_THRESHOLD,
 * copies the corpus entry's name into name_out and the score into
 * score_out, returning 1. Returns 0 if nothing met the threshold (or
 * no corpus loaded), -1 on a hashing error.
 *
 * Takes `fd` rather than a path - see handle_scan_request()'s comment
 * on why the whole scan/quarantine sequence now reads through one fd
 * opened once at the top, instead of re-resolving a path string at
 * each step. Hashes via a dup()'d handle so this doesn't disturb
 * `fd`'s own read offset for whatever the caller does with it next;
 * fuzzy_hash_file() seeks its handle to the start itself and restores
 * position when done, so no manual lseek is needed here either way.
 */
static int check_fuzzy_corpus(int fd, char *name_out, size_t name_out_len,
                              int *score_out) {
  char file_hash[FUZZY_MAX_RESULT];
  int best_score = -1;
  size_t best_idx = 0;
  size_t i;
  int dup_fd;
  FILE *fp;
  int hash_ret;

  if (fuzzy_corpus_count == 0)
    return 0;

  dup_fd = dup(fd);
  if (dup_fd < 0)
    return -1;

  fp = fdopen(dup_fd, "rb");
  if (!fp) {
    close(dup_fd);
    return -1;
  }

  hash_ret = fuzzy_hash_file(fp, file_hash);
  fclose(fp); /* also closes dup_fd */

  if (hash_ret != 0)
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
  int score;            /* sum of every matched rule's `weight` meta - see
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
                         void *message_data, void *user_data) {
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
      snprintf(ctx->rule_name + used, remaining, "%s%s", used > 0 ? "," : "",
               rule->identifier);
    }
    return CALLBACK_CONTINUE;
  }

  return CALLBACK_CONTINUE;
}

static int ensure_quarantine_dir(void) {
  if (mkdir(quarantine_dir, 0700) == 0)
    return 0;
  if (errno == EEXIST)
    return 0;
  fprintf(stderr, "avd: could not create quarantine dir \"%s\": %s\n",
          quarantine_dir, strerror(errno));
  return -1;
}

/* Fallback for quarantine_file()'s linkat() failing - see that
 * function's comment for the two real cases this covers (EXDEV:
 * quarantine dir on a different filesystem; ENOENT: the source's
 * link count already hit zero, e.g. an unlink()-then-replace race
 * rather than a rename()-away one - linkat(fd, "", ..., AT_EMPTY_PATH)
 * cannot resurrect a fully unlinked inode even though the fd itself
 * is still perfectly valid). Copies the already-open `fd`'s content
 * into `dst`, reading through `fd` rather than re-opening a path, so
 * this copy step itself reads the exact file that was scanned,
 * regardless of anything that may have happened to its original path
 * since - and regardless of which of the two cases above triggered
 * it. Does NOT unlink the original; the caller does that separately
 * once, since removing-by-path is the one operation here that still
 * has to re-resolve a path name and can't be done purely through `fd`
 * (see quarantine_file()'s identity re-check that guards it). */
static int copy_fd_to(int fd, const char *dst) {
  int out_fd;
  char buf[65536];
  ssize_t n;
  int ret = 0;

  if (lseek(fd, 0, SEEK_SET) < 0)
    return -1;

  out_fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (out_fd < 0)
    return -1;

  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    if (write(out_fd, buf, (size_t)n) != n) {
      ret = -1;
      break;
    }
  }
  if (n < 0)
    ret = -1;

  close(out_fd);

  if (ret != 0)
    unlink(dst); /* best-effort cleanup of the partial copy */

  return ret;
}

/*
 * Moves the already-open file `fd` into the quarantine directory and
 * chmod's it to 0000 (unreadable/unwritable/unexecutable by anyone,
 * including root without an explicit chmod back - a deliberate speed
 * bump against accidental re-execution, not real access control).
 * `path` is used for the destination's basename and log messages, and
 * for one narrow unlink described below - it does NOT drive identity
 * for the quarantine copy itself. Logs the outcome either way; a
 * quarantine failure does NOT block the verdict already being sent
 * back to the kernel for the kill.
 *
 * `fd` was opened once at the very top of handle_scan_request(),
 * before scanning even began, and has been read from (never
 * re-opened by path) for every step since - see that function's
 * comment. The quarantine copy is created via linkat(fd, "", ...,
 * AT_EMPTY_PATH) - this creates a new directory entry pointing at
 * fd's underlying inode DIRECTLY, without re-walking `path`, so it's
 * immune to the swap-the-path race the previous, path-only version of
 * this function could only narrow (lstat/rename gap, double-swap)
 * rather than close: there's nothing left here to swap out from under
 * an fd-identified link. This is the "more complete fix" that
 * function's comment used to point at as a follow-up.
 *
 * NOTE: a plain rename() through /proc/self/fd/N looks like it should
 * do the same thing and was tried first - it doesn't. Verified
 * empirically: it always fails with EXDEV, because the kernel treats
 * the source as living on procfs itself for the cross-device check
 * rather than transparently resolving to the real file's actual
 * filesystem. linkat()+AT_EMPTY_PATH is the primitive that actually
 * targets the fd's real inode.
 *
 * linkat() can fail for reasons that have nothing to do with a swap -
 * same-filesystem-only like any hardlink (EXDEV if the quarantine dir
 * is elsewhere), and it cannot resurrect a fully unlinked inode
 * (ENOENT once `fd`'s link count hits zero - a real, not just
 * theoretical, case: an unlink()-then-replace race hits this, a
 * rename()-away-then-replace race doesn't, and an attacker doesn't
 * owe us a choice between the two). copy_fd_to() below is the
 * fallback for any such failure, still reading through `fd` rather
 * than `path` either way. Once the quarantine copy exists (by
 * whichever route), removing the ORIGINAL by `path` is the one step left
 * that still has to re-walk it - unlink() has no fd-based equivalent
 * - so it gets a re-check-and-refuse immediately before it, comparing
 * the fd's true identity against a fresh lstat(). This is
 * risk-reduction, not elimination, for this one narrowed step - same
 * kind of tradeoff documented elsewhere in this codebase (see
 * Has_RWX_Segment's scope note) - but unlike the old design, a
 * mismatch here only means the original wasn't also cleaned up from
 * its old location, never that the wrong content got quarantined.
 */
static void quarantine_file(int fd, const char *path) {
  char dest[PATH_MAX];
  const char *base;
  struct timespec ts;
  struct stat fd_st;
  bool linked;

  if (ensure_quarantine_dir() != 0)
    return;

  base = strrchr(path, '/');
  base = base ? base + 1 : path;

  /* <pid>_<nanotime>_<base> rather than <epoch>_<base>: two files
   * with the same basename quarantined within the same wall-clock
   * second used to collide on this name, and the second link/copy
   * silently clobbered the first (avd is single-threaded today, but
   * this shouldn't quietly break if that ever changes). PID plus a
   * monotonic-clock nanosecond reading is unique per call even if
   * two quarantines land in the same second. */
  clock_gettime(CLOCK_MONOTONIC, &ts);
  snprintf(dest, sizeof(dest), "%s/%d_%ld%09ld_%s.quarantined", quarantine_dir,
           (int)getpid(), (long)ts.tv_sec, ts.tv_nsec, base);

  linked = (linkat(fd, "", AT_FDCWD, dest, AT_EMPTY_PATH) == 0);
  if (!linked) {
    /* Fall back to the fd-based copy on ANY linkat failure, not just
     * EXDEV - see copy_fd_to()'s comment for why ENOENT (source fully
     * unlinked, not just renamed away) is an equally real case here,
     * and the copy is correct regardless of which one triggered it. */
    int linkat_errno = errno;

    if (copy_fd_to(fd, dest) != 0) {
      fprintf(stderr,
              "avd: quarantine failed for \"%s\": linkat: %s; copy "
              "fallback: %s\n",
              path, strerror(linkat_errno), strerror(errno));
      return;
    }
  }

  /* Lock down the quarantine copy before touching the original at
   * all - this is what matters for "can this be re-executed". A
   * failed chmod means the copy is sitting there with whatever mode
   * the original had (potentially world-readable/executable), so
   * stop here rather than also removing the original: that would
   * trade a file we know the location and permissions of for one at
   * an unpredictable quarantine path that's LESS locked down, not
   * more. Best-effort remove the half-secured copy and leave the
   * original in place - a worse but at least contained outcome for
   * this specific (essentially unreachable in practice: this is a
   * freshly-created file we just opened successfully) failure. */
  if (chmod(dest, 0000) != 0) {
    fprintf(stderr, "avd: quarantined \"%s\" to \"%s\" but chmod failed: %s "
            "- leaving the original in place rather than removing it "
            "without a locked-down copy to show for it\n",
            path, dest, strerror(errno));
    unlink(dest);
    return;
  }

  /* Unlike the initial fd open at the top of handle_scan_request()
   * (which fails open on an inconclusive lstat - see that function's
   * comment), this fstat() is the immediate-pre-unlink recheck, and
   * gets the strict treatment: refuse rather than proceed if it
   * fails, matching this function's own stance everywhere else in
   * this recheck (a mismatch below also refuses). fstat() on our own
   * valid, already-successfully-read fd failing here would be
   * essentially unreachable in practice, but "essentially
   * unreachable" is exactly when failing closed instead of open costs
   * nothing and buys real margin. */
  if (fstat(fd, &fd_st) != 0) {
    fprintf(stderr,
            "avd: quarantined \"%s\" to \"%s\", but refusing to remove the "
            "original - fstat on our own fd failed unexpectedly: %s\n",
            path, dest, strerror(errno));
    return;
  }

  {
    struct stat now_st;

    /* This lstat()-then-unlink() pair is not, and cannot be made,
     * atomic through standard POSIX path-based syscalls - a swap
     * landing in the gap between this check and unlink() below (as
     * opposed to before it, which this check does catch) would still
     * remove whatever now occupies `path` instead of the original.
     * There is no portable "unlink iff this path still names inode X"
     * primitive to close that with. The alternative - doing this
     * removal from kernel space, where the already-resolved dentry
     * from detection could be unlinked directly - is deliberately out
     * of scope: see this file's top comment on why kernel-side
     * rename()/unlink() is the riskier direction, not the safer one,
     * for this codebase specifically. What's left is the same
     * risk-reduction-not-elimination tradeoff as every other
     * TOCTOU note in this codebase (see Has_RWX_Segment's scope
     * note): this check narrows the race to the syscall gap right
     * here instead of the whole scan-to-quarantine sequence, which is
     * what it was worth fixing for - it was never going to make
     * path-based removal provably atomic, and claiming otherwise
     * would be the actual bug. */
    if (lstat(path, &now_st) != 0 || now_st.st_dev != fd_st.st_dev ||
        now_st.st_ino != fd_st.st_ino) {
      fprintf(stderr,
              "avd: quarantined \"%s\" to \"%s\", but refusing to remove "
              "the original - path now resolves to a different file "
              "(possible symlink swap); remove it manually if "
              "appropriate\n",
              path, dest);
      return;
    }
  }

  if (unlink(path) != 0)
    fprintf(stderr, "avd: unlink of original \"%s\" failed: %s\n", path,
            strerror(errno));
  else
    printf("avd: QUARANTINED \"%s\" -> \"%s\"%s\n", path, dest,
           linked ? "" : " (copy fallback)");
}

static void handle_scan_request(uint64_t reqid, uint32_t pid, const char *path,
                                const char *sha256_hex) {
  struct yara_match_ctx ctx = {.matched = 0,
                               .match_count = 0,
                               .score = 0,
                               .override_matched = 0,
                               .rule_name = ""};
  int fd;
  int ret;

  printf("avd: scan request reqid=%llu pid=%u path=\"%s\" sha256=%s\n",
         (unsigned long long)reqid, pid, path, sha256_hex);

  /* Opened exactly once, here, before anything else touches the file.
   * The YARA scan, the fuzzy-hash check, and quarantine on a
   * MALICIOUS verdict all read/act through THIS fd from now on rather
   * than re-resolving `path` at each step - see quarantine_file()'s
   * comment for how the quarantine step itself uses it. An open fd keeps
   * referring to the exact same file for its entire lifetime
   * regardless of what happens to `path` afterward (deleted, renamed,
   * replaced with a symlink to something else - even during the scan
   * itself, which can take up to SCAN_TIMEOUT_SECS), so there's
   * nothing left for an attacker to swap out from under it. This
   * replaces the previous design's lstat-baseline-then-re-check-at-
   * rename-time approach, which could only narrow that window, not
   * close it. */
  fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "avd: could not open \"%s\" for scanning: %s\n", path,
            strerror(errno));
    send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
    return;
  }

  if (!compiled_rules) {
    send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
    close(fd);
    return;
  }

  ret = yr_rules_scan_fd(compiled_rules, fd, 0, yara_callback, &ctx,
                         SCAN_TIMEOUT_SECS);
  if (ret != ERROR_SUCCESS) {
    /* File vanished, permission denied, scan timeout, etc. - fail
     * open here too, matching the kernel side's own fail-open
     * stance on inconclusive information (see docs/netlink-protocol.md). */
    fprintf(stderr, "avd: yr_rules_scan_fd(\"%s\") failed: error %d\n", path,
            ret);
    send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
    close(fd);
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
      quarantine_file(fd, path);
      if (send_verdict(reqid, AV_VERDICT_MALICIOUS, ctx.rule_name) < 0)
        fprintf(stderr,
                "avd: failed to send MALICIOUS verdict for "
                "reqid=%llu \"%s\" - kernel side will fail "
                "open on timeout\n",
                (unsigned long long)reqid, path);
      close(fd);
      return;
    }

    printf("avd: %d rule(s) matched \"%s\" but score=%d is below "
           "threshold (%d) and no override rule fired - not "
           "convicting: \"%s\"\n",
           ctx.match_count, path, ctx.score, MALICIOUS_SCORE_THRESHOLD,
           ctx.rule_name);
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
    int fret =
        check_fuzzy_corpus(fd, fuzzy_name, sizeof(fuzzy_name), &fuzzy_score);

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

      snprintf(verdict_name, sizeof(verdict_name), "Fuzzy:%.40s(%d)",
               fuzzy_name, fuzzy_score);
      printf("avd: FUZZY MATCH \"%s\" -> \"%s\" score=%d\n", path, fuzzy_name,
             fuzzy_score);
      quarantine_file(fd, path);
      send_verdict(reqid, AV_VERDICT_MALICIOUS, verdict_name);
      close(fd);
      return;
    }
    if (fret < 0)
      fprintf(stderr, "avd: fuzzy hash of \"%s\" failed\n", path);
  }

  send_verdict(reqid, AV_VERDICT_CLEAN, NULL);
  close(fd);
}

/* Producer side (called only from msg_handler(), the netlink recv
 * thread). Copies the request into a heap task and blocks if the
 * queue is at AVD_SCAN_QUEUE_MAX rather than growing unbounded - this
 * is deliberate backpressure: if every worker is busy and the queue
 * is full, pausing the recv loop is no worse than the pre-fix
 * behavior (a scan already blocked the loop outright), and the
 * kernel's own DAEMON_TIMEOUT_MS still bounds how long any single
 * request waits before that side fails open. Returns false only on
 * shutdown or allocation failure, in which case the caller drops the
 * request (matching this codebase's existing fail-open stance). */
static bool enqueue_scan_task(uint64_t reqid, uint32_t pid, const char *path,
                              const char *sha256_hex) {
  struct scan_task *task = malloc(sizeof(*task));

  if (!task)
    return false;

  task->next = NULL;
  task->reqid = reqid;
  task->pid = pid;
  snprintf(task->path, sizeof(task->path), "%s", path ? path : "");
  snprintf(task->sha256_hex, sizeof(task->sha256_hex), "%s",
           sha256_hex ? sha256_hex : "");

  pthread_mutex_lock(&queue_lock);
  while (queue_len >= AVD_SCAN_QUEUE_MAX && !shutting_down)
    pthread_cond_wait(&queue_not_full, &queue_lock);

  if (shutting_down) {
    pthread_mutex_unlock(&queue_lock);
    free(task);
    return false;
  }

  if (queue_tail)
    queue_tail->next = task;
  else
    queue_head = task;
  queue_tail = task;
  queue_len++;
  pthread_cond_signal(&queue_not_empty);
  pthread_mutex_unlock(&queue_lock);

  return true;
}

/* Consumer side - runs on each of the AVD_SCAN_THREADS worker
 * threads. Blocks for work, exits once shutting_down is set AND the
 * queue has drained (rather than abandoning whatever's still queued,
 * since those requests are otherwise silently lost with no verdict
 * sent). */
static void *scan_worker_main(void *arg) {
  (void)arg;

  for (;;) {
    struct scan_task *task;

    pthread_mutex_lock(&queue_lock);
    while (!queue_head && !shutting_down)
      pthread_cond_wait(&queue_not_empty, &queue_lock);

    if (!queue_head && shutting_down) {
      pthread_mutex_unlock(&queue_lock);
      break;
    }

    task = queue_head;
    queue_head = task->next;
    if (!queue_head)
      queue_tail = NULL;
    queue_len--;
    pthread_cond_signal(&queue_not_full);
    pthread_mutex_unlock(&queue_lock);

    handle_scan_request(task->reqid, task->pid, task->path,
                        task->sha256_hex);
    free(task);
  }

  return NULL;
}

/* maxlen bounds are defense-in-depth, not the primary guard - msg_handler()
 * below already rejects anything not from the kernel (nlmsg_get_src()
 * check), and the kernel always sends AV_A_PATH/AV_A_SHA256 well within
 * these sizes (PATH_MAX and a 64-hex-char digest + NUL respectively, see
 * netlink_proto.h). Bounding them anyway means a future kernel-side bug
 * or protocol change can't hand this process an unbounded string to deal
 * with by accident. */
static struct nla_policy av_policy[AV_A_MAX + 1] = {
    [AV_A_REQID] = {.type = NLA_U64},
    [AV_A_PID] = {.type = NLA_U32},
    [AV_A_PATH] = {.type = NLA_STRING, .maxlen = AV_PATH_ATTR_MAXLEN},
    [AV_A_SHA256] = {.type = NLA_STRING, .maxlen = AV_SHA256_ATTR_MAXLEN + 1},
};

static int msg_handler(struct nl_msg *msg, void *arg) {
  (void)arg;
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  struct genlmsghdr *gnlh = nlmsg_data(nlh);
  struct nlattr *attrs[AV_A_MAX + 1];

  if (genlmsg_parse(nlh, 0, attrs, AV_A_MAX, av_policy) < 0) {
    fprintf(stderr, "avd: failed to parse incoming message\n");
    return NL_SKIP;
  }

  /* AV_C_SCAN_REQUEST must originate from the kernel (source portid ==
   * 0). Unlike AV_C_VERDICT on the kernel side (see the daemon_portid
   * check in netlink_chan.c's av_nl_verdict_doit()), nothing here
   * restricts who may unicast a message straight to this socket's
   * portid: this process never registers its own genl_family, so
   * GENL_ADMIN_PERM (which only gates access to a *kernel*-registered
   * .doit handler) doesn't apply to it at all. Any local process that
   * knows avd's portid - which defaults to avd's own pid via netlink
   * autobind, so it's as discoverable as `pgrep avd` - could otherwise
   * forge a SCAN_REQUEST with an arbitrary path/reqid directly to this
   * socket, bypassing the kernel (and any CAP_NET_ADMIN requirement)
   * entirely: flooding the bounded scan queue to starve real
   * detection, or directing this (typically root) daemon to
   * scan/quarantine a path of the attacker's choosing.
   *
   * MUST check nlmsg_get_src(msg)->nl_pid, NOT nlh->nlmsg_pid: the
   * latter is part of the message payload itself, written by whoever
   * constructed the message (our own kernel code happens to put 0
   * there via genlmsg_put()'s `port` argument, but nothing stops a
   * forged message from claiming the same value) - checking it
   * defeats the whole point of this guard, since the exact spoofer
   * this is meant to stop would just set that field to 0 themselves.
   * nlmsg_get_src() instead returns the sockaddr_nl the kernel itself
   * populated from the delivering socket's real, kernel-enforced
   * portid (via the recvmsg() call's out-of-band source address, same
   * trust boundary as genl_info->snd_portid on the kernel side) -
   * that's not attacker-writable. */
  if (gnlh->cmd == AV_C_SCAN_REQUEST) {
    struct sockaddr_nl *src = nlmsg_get_src(msg);

    if (!src || src->nl_pid != 0) {
      fprintf(stderr,
              "avd: SCAN_REQUEST from non-kernel portid %u ignored "
              "(possible spoofed request)\n",
              src ? src->nl_pid : (uint32_t)-1);
      return NL_SKIP;
    }
  }

  if (gnlh->cmd == AV_C_SCAN_REQUEST) {
    if (!attrs[AV_A_REQID] || !attrs[AV_A_PATH]) {
      fprintf(stderr, "avd: malformed SCAN_REQUEST (missing attrs)\n");
      return NL_SKIP;
    }
    if (!enqueue_scan_task(
            nla_get_u64(attrs[AV_A_REQID]),
            attrs[AV_A_PID] ? nla_get_u32(attrs[AV_A_PID]) : 0,
            nla_get_string(attrs[AV_A_PATH]),
            attrs[AV_A_SHA256] ? nla_get_string(attrs[AV_A_SHA256]) : ""))
      fprintf(stderr,
              "avd: dropped SCAN_REQUEST reqid=%llu (shutting down or "
              "out of memory) - kernel side will fail open on timeout\n",
              (unsigned long long)nla_get_u64(attrs[AV_A_REQID]));
  }

  return NL_OK;
}

static int register_with_kernel(void) {
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

int main(int argc, char **argv) {
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
    fprintf(stderr,
            "avd: could not resolve family \"%s\" - "
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

  {
    pthread_t workers[AVD_SCAN_THREADS];
    int i, spawned = 0;

    for (i = 0; i < AVD_SCAN_THREADS; i++) {
      if (pthread_create(&workers[i], NULL, scan_worker_main, NULL) != 0) {
        fprintf(stderr, "avd: pthread_create failed for worker %d: %s\n", i,
                strerror(errno));
        break;
      }
      spawned++;
    }
    if (spawned == 0) {
      fprintf(stderr, "avd: no scan workers could be started - aborting\n");
      nl_socket_free(sock);
      return 1;
    }
    if (spawned < AVD_SCAN_THREADS)
      fprintf(stderr,
              "avd: only %d/%d scan workers started - continuing with "
              "reduced concurrency\n",
              spawned, AVD_SCAN_THREADS);

    while (running) {
      int ret = nl_recvmsgs_default(sock);
      if (ret < 0 && ret != -NLE_INTR) {
        fprintf(stderr, "avd: nl_recvmsgs_default error: %s\n",
                nl_geterror(ret));
        break;
      }
    }

    printf("avd: shutting down, draining %zu queued scan(s)...\n", queue_len);
    pthread_mutex_lock(&queue_lock);
    shutting_down = true;
    pthread_cond_broadcast(&queue_not_empty);
    pthread_cond_broadcast(&queue_not_full);
    pthread_mutex_unlock(&queue_lock);

    for (i = 0; i < spawned; i++)
      pthread_join(workers[i], NULL);
  }

  nl_socket_free(sock);
  if (compiled_rules)
    yr_rules_destroy(compiled_rules);
  yr_finalize();
  free(fuzzy_corpus);
  return 0;
}
