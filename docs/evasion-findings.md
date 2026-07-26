# Evasion Resistance Findings (v0.9.0)

Four evasion techniques, one targeting each major detection layer,
tested against the actual engine (not hypothetical). Three were
verified standalone in a sandbox; the fourth needs the live kernel
module and is documented from the code logic plus a VM-runnable test
script (`tests/evasion/test_slow_drip_evasion.sh`).

## Summary table

| # | Technique | Target layer | Result |
|---|-----------|-------------|--------|
| 1 | Dynamic symbol resolution (`dlopen`/`dlsym`) | API heuristics (`heuristics.yar`) | **Evaded** the specific `Imports_Ptrace` rule; the evasion technique itself tripped a separate low-confidence rule (`Imports_Dlopen`) |
| 2 | Substantial file modification (+50KB random data) | Fuzzy hashing (`avd`'s corpus check) | **Fully evaded** — similarity score 0/100, vs. 100/100 for a minor (few-byte) variant |
| 3 | Entropy dilution (padding a packed binary with zero bytes) | Entropy analysis (`entropy.yar`) | **Evaded** the entropy check specifically, but the same file was still caught by structural analysis (`elf_analysis.yar`) — defense-in-depth held |
| 4 | Slow-drip file modification (bursts under threshold, paced past the window) | Behavioral heuristics (`behavior.c`) | **Evaded** by design of the fixed-window counter — not yet re-verified live in this writeup, see script and reasoning below |

## 1. Dynamic symbol resolution vs. API import heuristics

`rules/heuristics.yar`'s `Imports_Ptrace` rule checks YARA's `elf.dynsym`
table — the binary's static dynamic-symbol imports. Resolving `ptrace`
at runtime via `dlopen("libc.so.6")` + `dlsym(handle, "ptrace")` instead
of linking it directly means there's no direct import entry to find.

Verified: `objdump -T` on the evasion binary shows no `ptrace` entry;
`yara rules/heuristics.yar` produces no `Imports_Ptrace` match.

**Interesting nuance**: the evasion technique itself isn't free —
`Imports_Dlopen` (a rule explicitly marked "very low confidence, do not
alert on this alone" since `dlopen` is ubiquitous in legitimate
software) still fires. This doesn't mean the evasion failed — `dlopen`
alone is far too common to act on — but it's a reminder that evasion
techniques can leave their own fingerprints, and a more sophisticated
engine could build a meta-heuristic specifically for "uses dynamic
symbol resolution instead of static linking for a small number of
specific functions" as its own (still weak, but non-zero) signal.

**Mitigation directions** (not implemented, discussion only): scanning
`.rodata`/string sections for the literal string `"ptrace"` alongside
the import check would catch this specific case (the string still has
to appear somewhere for `dlsym` to look it up) — though that's
defeatable too (string obfuscation, building the name character-by-
character at runtime). This is a genuine cat-and-mouse dynamic, worth
stating plainly rather than implying any static analysis is airtight.

## 2. Substantial modification vs. fuzzy hashing

Fuzzy hashing (CTPH/ssdeep) is explicitly designed to tolerate *minor*
changes — the v0.7.0 testing already showed a few appended bytes
scoring 100/100 similarity. This test checked the boundary: how much
change breaks it?

Verified: appending 50KB of random data to a ~16KB binary (roughly
tripling its size with unrelated content) dropped the similarity score
to 0/100 — full evasion, using the exact `fuzzy_compare()` call `avd.c`
uses.

**This is expected, not a bug.** CTPH is a rolling-hash, block-based
similarity measure — it's designed to detect "this is basically the
same file with small edits," not "this file shares some heritage with
that one." A well-known, honest limitation of the technique, not
specific to this implementation. Real-world malware families that get
substantially repacked/recompiled between variants will evade a
fuzzy-hash corpus check the same way, which is exactly why this project
treats fuzzy hashing as one signal among several rather than a
standalone detector.

## 3. Entropy dilution vs. entropy analysis — testing defense-in-depth

This is the most important finding of the four, because it tests the
project's core design premise directly: **does evading one layer mean
evading the engine?**

Padding a UPX-packed binary with 500KB of zero bytes dilutes the
*whole-file* Shannon entropy average below the 7.0 threshold —
verified: `entropy.yar`'s `High_Overall_Entropy` no longer fires on the
padded file.

But the same padded file was run through `elf_analysis.yar` and both
`No_Section_Headers` and `Entry_Point_Outside_Text` still fired —
because padding the file with zero bytes doesn't restore the section
headers UPX stripped, or fix the entry point. **Evading the entropy
check did not evade the engine.**

This is the strongest argument in the whole project for layering
independent, differently-mechanismed checks rather than relying on any
single detector, and worth making explicitly in your report as the
central design validation of `v0.3.0`–`v0.8.0` being separate systems
rather than one big scoring function.

## 4. Slow-drip modification vs. rapid-write behavioral heuristic

`behavior.c`'s rapid-write counter uses a **fixed window**, not a true
sliding window:

```c
if (e->window_start_jiffies == 0 || window_ms > WRITE_OPEN_WINDOW_MS) {
    e->window_start_jiffies = jiffies;  /* window resets ENTIRELY */
    e->write_open_count = 1;
} else {
    e->write_open_count++;
    ...
}
```

Once more than 2 seconds have passed since the window started, the
counter resets to 1 regardless of how many writes happened — there's
no memory of activity in the *previous* window. A process that writes
49 files, waits just over 2 seconds, writes another 49, waits, and
repeats indefinitely will never cross the threshold in any single
window, no matter how many files it modifies in total over time.

**This is a structural limitation, not a threshold-tuning problem** —
raising or lowering `WRITE_OPEN_THRESHOLD` doesn't fix it, since the
evasion works by pacing around whatever the window boundary is. A true
sliding window (tracking a rolling count over the last N milliseconds,
recomputed continuously rather than reset in discrete blocks) would
close this gap; it's meaningfully more complex to implement correctly
in kernel space (needs either a timestamp per event or a decaying
counter, not just two integers) and was out of scope here — a good
`v0.8.1`/future-work item to name explicitly rather than leave
implicit.

`tests/evasion/test_slow_drip_evasion.sh` is ready to run against the
live module in a VM to confirm this empirically; the reasoning above
is derived directly from the code path, not yet re-confirmed with a
fresh dmesg capture at time of writing.

## Overall takeaways for the report

- Every individual detection layer has a known, demonstrable evasion.
  This is expected and honest — no single technique here is claimed to
  be unbeatable, and presenting them as if they were would be the
  wrong takeaway.
- The one deliberately-designed defense (layering independent checks)
  held up under direct testing (finding #3) — evading entropy analysis
  did not evade the structural analysis running alongside it.
- The behavioral heuristic's evasion (#4) is the one with a *known,
  named* structural fix (true sliding window) rather than being an
  inherent limit of the underlying technique (as #1 and #2 arguably
  are) — worth distinguishing "we ran out of scope" from "this is as
  good as this approach gets" when discussing each finding.
