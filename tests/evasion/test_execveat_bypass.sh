#!/usr/bin/env bash
#
# test_execveat_bypass.sh - execveat() coverage test (post-fix
# regression, not really an "evasion" in the adversarial sense the
# other scripts in this dir test - included here because until the
# execveat kprobe was added, calling execveat() instead of execve()
# was a complete, trivial bypass of every exec-based check: no
# hash/signature match, no daemon scan, no av_behavior_record_exec()
# call at all).
#
# Technique: glibc has no execveat() wrapper, so this calls the raw
# syscall directly via syscall(SYS_execveat, ...). Covers three cases
# that mirror bugs already found and fixed elsewhere in this codebase
# for other syscalls (execve's relative-path fix, openat's dfd-ignored
# fix):
#
#   1. AT_FDCWD + absolute path   - the plain case
#   2. AT_FDCWD + relative path   - cwd resolution
#   3. real dfd + relative path   - dfd resolution (openat's bug, for exec)
#
# ...plus a fourth, DOCUMENTED-GAP case that is expected to NOT be
# caught and does not count as a test failure:
#
#   4. memfd_create() + AT_EMPTY_PATH - fileless exec. pathname is
#      empty and dfd has no resolvable filesystem path, so
#      hash_file_multi()/open_exec_target() has nothing to open. See
#      handler_pre_execveat()'s comment in av/main.c.
#
# NEEDS THE LIVE KERNEL MODULE - run this in your VM, not standalone.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "This script needs root to check dmesg meaningfully after the test."
	echo "Re-run with sudo."
	exit 1
fi

if [ ! -d /sys/module/av ]; then
	echo "av.ko doesn't appear to be loaded - insmod it first:"
	echo "  sudo insmod av/av.ko"
	exit 1
fi

TESTDIR=/tmp/execveat_test
mkdir -p "$TESTDIR"

PASS=0
FAIL=0

echo "=== execveat() coverage test ==="
echo

# ---- build the raw-syscall runner ----

cat >/tmp/execveat_runner.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

/* Usage: execveat_runner <dfd-path-or-"AT_FDCWD"-or-"memfd"> <pathname> <flags> */
int main(int argc, char *argv[])
{
    int dfd;
    const char *path = argv[2];
    int flags = atoi(argv[3]);
    char *const av_[2] = { NULL, NULL };
    char *const ev_[1] = { NULL };

    if (!strcmp(argv[1], "AT_FDCWD")) {
        dfd = AT_FDCWD;
    } else if (!strcmp(argv[1], "memfd")) {
        /* Fileless exec: copy the EICAR file into an anonymous memfd,
         * exec it via dfd=memfd_fd, pathname="", AT_EMPTY_PATH. */
        FILE *src = fopen(path, "rb");
        char buf[256];
        size_t n;

        if (!src) { perror("fopen"); return 1; }
        dfd = syscall(SYS_memfd_create, "execveat_test", 0);
        if (dfd < 0) { perror("memfd_create"); return 1; }
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            write(dfd, buf, n);
        fclose(src);
        path = "";
        flags |= 0x1000; /* AT_EMPTY_PATH */
    } else {
        dfd = open(argv[1], O_RDONLY | O_DIRECTORY);
        if (dfd < 0) { perror("open dfd"); return 1; }
    }

    av_[0] = (char *)path;
    syscall(SYS_execveat, dfd, path, av_, ev_, flags);
    perror("execveat"); /* only reached if execveat itself failed */
    return 1;
}
EOF
gcc -o /tmp/execveat_runner /tmp/execveat_runner.c

# ---- shared EICAR fixture ----

printf "X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" >/tmp/eicar.com
chmod +x /tmp/eicar.com

check_detected() {
	local expect_path="$1"
	if dmesg | tail -20 | grep -q "DETECTED \"$expect_path\""; then
		return 0
	fi
	return 1
}

# ---- Test 1: AT_FDCWD + absolute path ----

echo "-- Test 1: AT_FDCWD + absolute path --"
dmesg -C
/tmp/execveat_runner AT_FDCWD /tmp/eicar.com 0 || true
sleep 1
if check_detected "/tmp/eicar.com"; then
	echo "PASS: detected via AT_FDCWD + absolute path"
	PASS=$((PASS + 1))
else
	echo "FAIL: no detection - check the execveat kprobe symbol/register"
	echo "      mapping first (sudo cat /proc/kallsyms | grep sys_execveat)"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 2: AT_FDCWD + relative path ----

echo "-- Test 2: AT_FDCWD + relative path --"
dmesg -C
(cd /tmp && /tmp/execveat_runner AT_FDCWD eicar.com 0 || true)
sleep 1
if check_detected "/tmp/eicar.com"; then
	echo "PASS: relative path resolved against cwd correctly"
	PASS=$((PASS + 1))
else
	echo "FAIL: relative path not resolved (or resolved to the wrong string) -"
	echo "      check that aw->pwd is actually being set from resolve_dfd_path()"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 3: real dfd + relative path ----

echo "-- Test 3: real dfd + relative path --"
mkdir -p "$TESTDIR/subdir"
cp /tmp/eicar.com "$TESTDIR/subdir/eicar.com"
dmesg -C
/tmp/execveat_runner "$TESTDIR/subdir" eicar.com 0 || true
sleep 1
if check_detected "$TESTDIR/subdir/eicar.com"; then
	echo "PASS: dfd-relative path resolved correctly"
	PASS=$((PASS + 1))
else
	echo "FAIL: dfd was ignored/mishandled - this is openat's dfd-ignored bug's"
	echo "      exact counterpart for exec; check resolve_dfd_path()'s return"
	echo "      value path in handler_pre_execveat(), not the hashing logic"
	FAIL=$((FAIL + 1))
fi
echo

# ---- Test 4: memfd + AT_EMPTY_PATH (documented gap, informational only) ----

echo "-- Test 4: memfd + AT_EMPTY_PATH (fileless exec - documented gap) --"
dmesg -C
/tmp/execveat_runner memfd /tmp/eicar.com 0 || true
sleep 1
echo "--- dmesg from this run (informational - not a pass/fail check) ---"
dmesg | tail -10
echo
echo "This case is NOT expected to be caught yet - pathname is empty and dfd"
echo "has no resolvable filesystem path, so open_exec_target() has nothing to"
echo "open. Documented as a known limitation in handler_pre_execveat()'s"
echo "comment in av/main.c, same way the openat() open()-vs-open_at() gap and"
echo "Has_RWX_Segment's unverified status are documented rather than silently"
echo "left out. Worth including this dmesg output verbatim in the report as"
echo "the boundary of what this patch covers."
echo

# ---- summary ----

rm -f /tmp/execveat_runner /tmp/execveat_runner.c /tmp/eicar.com
rm -rf "$TESTDIR"

echo "=== Summary: $PASS passed, $FAIL failed (Test 4 excluded - informational) ==="
if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
