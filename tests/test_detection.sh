#!/usr/bin/env bash
#
# tests/test_detection.sh - end-to-end integration test: builds the module,
# loads it, runs a known-clean command and the EICAR test file, checks
# dmesg for the expected outcome, then unloads.
#
# RUN THIS ONLY IN YOUR VM, ideally from a fresh snapshot. It loads a
# kernel module - if there's a regression this script won't catch, the
# usual kernel-module risks apply (see top-level README).
#
# Usage: sudo tests/test_detection.sh
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod/rmmod). Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AV_DIR="$REPO_ROOT/av"
EICAR_PATH="/tmp/av_test_eicar.com"
EICAR_HASH="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# A module MUST be built with the same compiler family as the running
# kernel (see the top-level README's toolchain section) - e.g. CachyOS
# ships kernels built with Clang. We can't rely on inherited CC/LLVM
# environment variables here: this script is meant to run under sudo
# (for insmod/rmmod), and sudo resets the environment by default,
# stripping any CC=clang LLVM=1 the user had exported. Detecting the
# running kernel's actual build toolchain directly is robust regardless
# of how this script gets invoked or what the caller's shell had set.
MAKE_ARGS=()
if grep -q "clang version" /proc/version 2>/dev/null; then
    echo "Detected a Clang-built running kernel ($(uname -r)) - building with CC=clang LLVM=1"
    MAKE_ARGS=(CC=clang LLVM=1)
fi

cleanup() {
    section "cleanup"
    rmmod av 2>/dev/null && echo "  module unloaded" || echo "  module already unloaded"
    rm -f "$EICAR_PATH"
}
trap cleanup EXIT

section "build"
if make -C "$AV_DIR" "${MAKE_ARGS[@]}" clean >/tmp/build.log 2>&1 && \
   make -C "$AV_DIR" "${MAKE_ARGS[@]}" >>/tmp/build.log 2>&1; then
    pass "module built"
else
    fail "build failed - see /tmp/build.log"
    cat /tmp/build.log
    exit 1
fi

section "load"
if insmod "$AV_DIR/av.ko" 2>/tmp/insmod.log; then
    pass "module loaded"
else
    fail "insmod failed: $(cat /tmp/insmod.log)"
    exit 1
fi
sleep 1

section "clean-file sanity check (should NOT be killed, should log as clean)"
dmesg -C  # clear dmesg so we only see events from this point on
/bin/ls >/dev/null
sleep 1
if dmesg | grep -q 'event=clean.*path="/bin/ls"'; then
    pass "clean file logged as clean"
else
    fail "expected clean-file log line not found in dmesg"
fi
if dmesg | grep -q 'event=detected.*path="/bin/ls"'; then
    fail "clean file was incorrectly flagged as a detection"
else
    pass "clean file was not flagged"
fi

section "EICAR detection"
# Single quotes are intentional: this string has literal $ characters
# that must NOT be shell-expanded.
# shellcheck disable=SC2016
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$EICAR_PATH"
chmod +x "$EICAR_PATH"

ACTUAL_HASH="$(sha256sum "$EICAR_PATH" | awk '{print $1}')"
if [ "$ACTUAL_HASH" = "$EICAR_HASH" ]; then
    pass "EICAR file hash matches expected value"
else
    fail "EICAR file hash mismatch: got $ACTUAL_HASH, expected $EICAR_HASH"
fi

dmesg -C
"$EICAR_PATH" >/dev/null 2>&1
sleep 1   # detection is async (workqueue) - give it a moment

if dmesg | grep -qi 'event=detected.*action=kill.*reason="signature:EICAR-Test-File"'; then
    pass "EICAR execution was detected and killed"
else
    fail "expected DETECTED/killing log line not found in dmesg"
    dmesg | tail -10
fi

section "unload"
if rmmod av 2>/tmp/rmmod.log; then
    pass "module unloaded cleanly"
else
    fail "rmmod failed: $(cat /tmp/rmmod.log)"
fi
trap - EXIT   # already handled above

echo
echo "==================================="
echo "detection tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
