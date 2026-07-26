#!/usr/bin/env bash
#
# test_entropy_dilution_evasion.sh - v0.9.0 evasion test 3.
#
# Technique: pad a packed (high-entropy) binary with a large amount of
# low-entropy filler (zero bytes) to dilute the WHOLE-FILE Shannon
# entropy average below the 7.0 threshold.
#
# The interesting question isn't just "does this evade entropy.yar" -
# it's "does evading ONE layer mean evading the whole engine", since
# this project's design is explicitly layered (v0.3.0-v0.8.0 are
# separate, independent checks). This test checks BOTH.
#
# Runs standalone - no kernel module needed, just the yara CLI + upx.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "=== Evasion test: entropy dilution (padding a packed binary) ==="

if [ ! -f /tmp/ptrace_test ]; then
    cat > /tmp/ptrace_test.c << 'EOF'
#include <sys/ptrace.h>
#include <stddef.h>
int main(void) { ptrace(PTRACE_ATTACH, 1234, NULL, NULL); return 0; }
EOF
    gcc -o /tmp/ptrace_test /tmp/ptrace_test.c
fi

if ! command -v upx >/dev/null 2>&1; then
    echo "upx not installed - install upx-ucl (apt) or upx (pacman) to run this test"
    exit 1
fi

upx --best -o /tmp/upx_packed_evasion /tmp/ptrace_test >/dev/null 2>&1

echo
echo "--- baseline: packed binary, unmodified ---"
yara "$REPO_ROOT/rules/entropy.yar" /tmp/upx_packed_evasion
echo "(expect: High_Overall_Entropy)"

echo
echo "--- evasion attempt: pad with 500KB of zero bytes ---"
cp /tmp/upx_packed_evasion /tmp/entropy_evasion
head -c 500000 /dev/zero >> /tmp/entropy_evasion

ENTROPY_RESULT="$(yara "$REPO_ROOT/rules/entropy.yar" /tmp/entropy_evasion || true)"
if echo "$ENTROPY_RESULT" | grep -q High_Overall_Entropy; then
    echo "entropy.yar: still fired - entropy evasion FAILED"
    ENTROPY_EVADED=0
else
    echo "entropy.yar: no match - entropy check evaded"
    ENTROPY_EVADED=1
fi

echo
echo "--- but does the STRUCTURAL check (elf_analysis.yar) still catch it? ---"
STRUCT_RESULT="$(yara "$REPO_ROOT/rules/elf_analysis.yar" /tmp/entropy_evasion || true)"
echo "$STRUCT_RESULT"

echo
if [ "$ENTROPY_EVADED" -eq 1 ] && echo "$STRUCT_RESULT" | grep -q .; then
    echo "RESULT: entropy check evaded, BUT structural rules still caught the"
    echo "same file - defense-in-depth held. Evading one layer of a layered"
    echo "detection engine is not the same as evading the engine."
elif [ "$ENTROPY_EVADED" -eq 1 ]; then
    echo "RESULT: entropy check evaded AND no other rule caught it either -"
    echo "genuine full evasion of this sample."
else
    echo "RESULT: entropy dilution did not work as expected."
fi
