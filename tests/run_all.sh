#!/usr/bin/env bash
#
# tests/run_all.sh - builds everything and runs both test scripts.
# Used by .githooks/pre-push, and safe to run manually any time:
#   sudo tests/run_all.sh
#
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run_all.sh needs root (insmod/rmmod). Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0

echo "### building avctl ###"
make -C "$REPO_ROOT/userspace/avctl" || FAIL=1

echo
echo "### test_detection.sh (build av/, load, exercise clean+EICAR, unload) ###"
"$REPO_ROOT/tests/test_detection.sh" || FAIL=1

echo
echo "### test_sigtable.sh (avctl/proc protocol) ###"
# test_detection.sh unloads the module as part of its own cleanup, so
# reload it here for the sigtable protocol tests.
insmod "$REPO_ROOT/av/av.ko" 2>/dev/null || true
"$REPO_ROOT/tests/test_sigtable.sh" || FAIL=1
rmmod av 2>/dev/null || true

echo
if [ "$FAIL" -ne 0 ]; then
    echo "run_all.sh: one or more test suites FAILED"
    exit 1
fi

echo "run_all.sh: all test suites passed"
exit 0
