#!/usr/bin/env bash
#
# test_fuzzy_evasion.sh - v0.9.0 evasion test 2.
#
# Technique: fuzzy hashing (ssdeep/CTPH) tolerates MINOR modifications
# (a few appended bytes score ~100 similarity, per the v0.7.0 testing
# section) but this tests whether SUBSTANTIAL modification defeats it
# entirely - appending a large amount of data relative to the original
# file size.
#
# Runs standalone - no kernel module needed, just ssdeep/libfuzzy.
#
set -euo pipefail

echo "=== Evasion test: fuzzy hash evasion via substantial modification ==="

if [ ! -f /tmp/ptrace_test ]; then
    cat > /tmp/ptrace_test.c << 'EOF'
#include <sys/ptrace.h>
#include <stddef.h>
int main(void) { ptrace(PTRACE_ATTACH, 1234, NULL, NULL); return 0; }
EOF
    gcc -o /tmp/ptrace_test /tmp/ptrace_test.c
fi

ssdeep -b /tmp/ptrace_test > /tmp/corpus_seed.txt

echo
echo "--- baseline: minor modification (few bytes appended) ---"
cp /tmp/ptrace_test /tmp/minor_variant
echo "small change" >> /tmp/minor_variant
ssdeep -m /tmp/corpus_seed.txt /tmp/minor_variant || echo "(no match - unexpected for a minor variant)"

echo
echo "--- evasion attempt: substantial modification (+50KB random data," \
     "original file is ~16KB) ---"
cp /tmp/ptrace_test /tmp/heavy_variant
head -c 50000 /dev/urandom >> /tmp/heavy_variant

RESULT="$(ssdeep -m /tmp/corpus_seed.txt /tmp/heavy_variant || true)"
if [ -n "$RESULT" ]; then
    echo "$RESULT"
    echo
    echo "RESULT: still matched - evasion FAILED"
else
    echo "(no match reported)"
    echo
    echo "RESULT: fuzzy hash evaded successfully"
fi

echo
echo "--- exact similarity score (via libfuzzy C API, same as avd.c uses) ---"
cat > /tmp/fuzzy_score_check.c << 'EOF'
#include <stdio.h>
#include <fuzzy.h>
int main(int argc, char **argv) {
    char h1[FUZZY_MAX_RESULT], h2[FUZZY_MAX_RESULT];
    fuzzy_hash_filename(argv[1], h1);
    fuzzy_hash_filename(argv[2], h2);
    printf("similarity score: %d/100\n", fuzzy_compare(h1, h2));
    return 0;
}
EOF
gcc -o /tmp/fuzzy_score_check /tmp/fuzzy_score_check.c -lfuzzy
/tmp/fuzzy_score_check /tmp/ptrace_test /tmp/heavy_variant
