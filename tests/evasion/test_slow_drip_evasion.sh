#!/usr/bin/env bash
#
# test_slow_drip_evasion.sh - v0.9.0 evasion test 4.
#
# Technique: behavior.c's rapid-write-open counter uses a FIXED window,
# not a true sliding window - see av_behavior_check_openat():
#
#   if (e->window_start_jiffies == 0 || window_ms > WRITE_OPEN_WINDOW_MS) {
#       e->window_start_jiffies = jiffies;  // window resets entirely
#       e->write_open_count = 1;
#   } else {
#       e->write_open_count++;
#       ...
#   }
#
# This means a process can write up to WRITE_OPEN_THRESHOLD (50) files
# within any single 2-second window, then pause briefly for the window
# to reset, and repeat INDEFINITELY - modifying an arbitrary number of
# files over time without ever exceeding the per-window threshold. This
# is a real, structural limitation of fixed/discrete-window rate
# limiting (as opposed to a true sliding window), not a tuning problem
# fixable by adjusting the threshold number alone.
#
# NEEDS THE LIVE KERNEL MODULE - run this in your VM, not standalone.
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root to check dmesg meaningfully after the test."
    echo "Re-run with sudo, or just run the write loop below manually and"
    echo "check 'dmesg | tail' yourself."
fi

TESTDIR=/tmp/slow_drip_test
mkdir -p "$TESTDIR"
cd "$TESTDIR"

echo "=== Evasion test: slow-drip file modification ==="
echo "Writing 200 files total, in bursts of 40 (under the 50 threshold),"
echo "with a 2.1 second pause between bursts (just over the window size)."
echo

dmesg -C 2>/dev/null || true

BURST_SIZE=40
NUM_BURSTS=5

for burst in $(seq 1 "$NUM_BURSTS"); do
    echo "-- burst $burst/$NUM_BURSTS ($BURST_SIZE files --"
    for i in $(seq 1 "$BURST_SIZE"); do
        echo "data" > "burst${burst}_file${i}.txt"
    done
    if [ "$burst" -lt "$NUM_BURSTS" ]; then
        echo "   pausing 2.1s for the window to reset..."
        sleep 2.1
    fi
done

TOTAL=$((BURST_SIZE * NUM_BURSTS))
echo
echo "Wrote $TOTAL files total across $NUM_BURSTS bursts."
echo
echo "--- dmesg since the test started ---"
dmesg 2>/dev/null | tail -20 || echo "(run 'dmesg | tail -20' manually if not root)"

echo
echo "EXPECTED RESULT: no 'rapid file modification' kill, despite modifying"
echo "$TOTAL files total - each individual burst stayed under the 50-open"
echo "threshold, and the fixed window reset between bursts. This is the"
echo "real limitation: total volume over time isn't tracked, only volume"
echo "within whichever single window is currently active."
