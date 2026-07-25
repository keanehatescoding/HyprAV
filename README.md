# Kernel-Level Linux Antivirus — Final Year Project

A Linux kernel-level antivirus built incrementally: starting from bare LKM
basics, through kprobe-based syscall hooking, to signature-based detection
and (later) behavioral heuristics. `av/` is the single evolving module —
milestones are marked with git tags, not parallel folders.

**All development and testing happens inside a VM.** Kernel modules can and
will crash your kernel while you learn — snapshot your VM before every test
run.

```
snapshot the VM
insmod av.ko
test
dmesg | tail -50
rmmod av
# if it panics/hangs: restore snapshot, fix, repeat
```

## Repo layout

```
.githooks/
  pre-commit          - lint on commit (fast, no build)
  pre-push            - full test suite on push (only if av/ or avctl changed)
scripts/
  setup-hooks.sh       - one-time: git config core.hooksPath .githooks
docs/
  netlink-protocol.md  - kernel<->daemon protocol design (commands, attrs, flow)
av/                  - the actual antivirus module (single, evolving)
  main.c              - kprobe hook, workqueue, multi-algorithm hashing
  sigtable.c/.h       - kernel hashtable signature store + /proc interface
  netlink_chan.c/.h   - Generic Netlink channel to avd (see docs/netlink-protocol.md)
  netlink_proto.h     - protocol definitions shared with userspace/avd
  Makefile
rules/
  test.yar             - sample YARA rules used for testing avd (EICAR string
                        match, a toy reverse-shell pattern)
  heuristics.yar        - v0.4.0: API import heuristics using YARA's elf
                        module (ptrace, memfd_create, mprotect, dlopen,
                        plus a compound rule) - see the confidence notes
                        in the file, these are individually weak signals
  elf_analysis.yar      - v0.5.0: ELF structural analysis (no section
                        headers, executable stack, RWX segments, entry
                        point outside .text) - higher confidence than
                        heuristics.yar, verified against a real UPX-packed
                        binary
  entropy.yar           - v0.6.0: whole-file and per-section Shannon
                        entropy - threshold (7.0/8.0) calibrated against
                        real samples, catches packers that strip AND
                        packers that keep section headers
userspace/
  avctl/              - CLI for managing the signature DB via /proc
    avctl.c
    Makefile
  avd/                - daemon: receives scan requests over netlink, loads
                        rules/*.yar at startup, replies with a verdict based
                        on YARA matching
    avd.c
    Makefile
experiments/          - throwaway learning modules, not tagged/released
  hello/              - minimal LKM: module_init/module_exit, dmesg logging
  procfs_demo/        - /proc entry you can read/write from userspace
  kprobe_log/         - kprobe on execve that just logs filenames (no blocking)
tests/
  test_sigtable.sh     - avctl/proc protocol tests (add/list/del/reject)
  test_detection.sh    - full build/load/detect/unload integration test
  run_all.sh           - runs both of the above (used by the pre-push hook)
```

## Architecture: what lives in the kernel vs. userspace

Most of the roadmap below is deliberately **not** kernel code. The kernel
module's job is narrow: intercept execve/file events cheaply, do fast
checks (hash lookup, simple counters), and enforce (kill/deny). Anything
slow, complex, or using large libraries — YARA matching, ELF parsing,
entropy math, fuzzy hashing — belongs in a userspace daemon that the
kernel module talks to (via `/proc`, `debugfs`, or netlink), for the same
reason the workqueue fix mattered: you don't want blocking, heavyweight,
or crash-prone logic running in kernel context on every process launch.

## Releases

Milestones are marked with annotated git tags on `av/`, not separate
directories.

| Tag | Feature | Where it lives |
|-----|---------|-----------------|
| `v0.1.0` ✅ | Hash-based detection (SHA-256), kprobe execve hook, kill on match | kernel |
| `v0.2.0` ✅ | Multi-algorithm hashing (MD5, SHA-1, SHA-256) + signature DB moved to a kernel hashtable, managed at runtime via `/proc/kernel_av_signatures` (or the `avctl` CLI) | kernel + `avctl` CLI |
| `v0.3.0-prep` ✅ | Kernel↔daemon Generic Netlink channel (`netlink_chan.c`, `avd` skeleton) — plumbing, verified against real kernel/libnl headers | kernel + `avd` |
| `v0.3.0` ✅ | Real YARA rule scanning — `avd` loads `rules/*.yar` and scans on a signature miss; verified against a real EICAR match at runtime | userspace daemon (libyara) |
| `v0.4.0` ✅ | String & API heuristics via YARA's `elf` module (imported dynamic symbols: `ptrace`, `memfd_create`, `mprotect`, `dlopen`, plus a compound rule) — verified against real ptrace-importing binaries | userspace (`rules/heuristics.yar`) |
| `v0.5.0` ✅ | ELF header & section analysis — no section headers (packer indicator), executable stack, RWX segments, entry point outside `.text` — verified against a real UPX-packed binary | userspace (`rules/elf_analysis.yar`) |
| `v0.6.0` ✅ | Entropy analysis — whole-file and per-section Shannon entropy, threshold calibrated against real samples (normal binary, packed binary, random data) | userspace (`rules/entropy.yar`) |
| `v0.7.0` | Fuzzy hashing (ssdeep/TLSH) against a known-sample corpus | userspace |
| `v0.8.0` | Behavioral heuristics (rapid file writes, sensitive path writes, self-deleting binaries) | kernel (workqueue-deferred, same pattern as v0.1.0) |
| `v0.9.0` | Evasion resistance — adversarial testing against your own engine (packing, obfuscation, timing-based sandbox detection) and documenting what does/doesn't get caught | test suite + report, not shipped code |
| `v1.0.0` | Quarantine policy, structured logging, performance benchmarks | kernel + userspace |

`v0.3.0-prep` is worth tagging on its own once verified — see
`docs/netlink-protocol.md` for the full protocol design, including a
documented fail-open-on-timeout decision worth discussing in your report.

Tagging a milestone once it's working and tested:

```bash
git add av/
git commit -m "av: signature-based execve detection"
git tag -a v0.1.0 -m "Signature detection MVP: kprobe execve hook, in-kernel SHA-256, hardcoded signature list"
git push origin main --tags
```

Then cut a GitHub Release from that tag (Releases → Draft a new release →
pick the tag) with notes on what changed and how you tested it — this is
good material to point to directly in your project report/demo.

## Prerequisites (inside the VM)

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) git
```

## Building

```bash
cd av              # or experiments/hello, experiments/procfs_demo, etc.
make
sudo insmod av.ko
dmesg | tail -20
sudo rmmod av
```

## A note on kernel version / architecture

The kprobe-based modules (`experiments/kprobe_log`, `av/`) hook the syscall
entry point by symbol name. On x86_64 kernels 5.7+, the actual syscall
wrapper is named `__x64_sys_execve` and its argument layout differs from
older kernels (arguments live inside an inner `struct pt_regs`, not
directly in the outer one, due to the syscall wrapper macro). The code here
targets that modern x86_64 layout. If you're on arm64, the symbol is
`__arm64_sys_execve` instead — check with:

```bash
sudo cat /proc/kallsyms | grep sys_execve
```

and adjust `HOOKED_SYSCALL_NAME` in the source accordingly.

## Git hooks (lint on commit, full tests on push)

One-time setup after cloning:

```bash
scripts/setup-hooks.sh
```

This points git at the tracked hooks in `.githooks/` instead of the
default untracked `.git/hooks/`:

- **pre-commit** — fast lint only (cppcheck on `av/` and
  `userspace/avctl/`, `gcc -fsyntax-only` on the CLI, shellcheck on test
  scripts). No build, no insmod — stays quick so it doesn't discourage
  committing.
- **pre-push** — runs `tests/run_all.sh` (build, insmod, EICAR
  detection, unload) via sudo, but **only** when the push actually
  touches `av/` or `userspace/avctl/` — a docs-only push won't load a
  kernel module.

Both are bypassable with `--no-verify` if you genuinely need to, but
avoid that right before tagging a release.

## Automated tests

`tests/` has two scripts — both run *inside your VM*, not in CI (see
the CI section below for why):

- **`test_sigtable.sh`** — exercises the `avctl`/`/proc` protocol: add,
  list, del, and rejection of malformed input. Run against an
  already-loaded module:
  ```bash
  sudo insmod av/av.ko    # if not already loaded
  cd userspace/avctl && make && cd ../..
  tests/test_sigtable.sh
  ```

- **`test_detection.sh`** — full integration test: builds the module,
  loads it, runs a known-clean command and verifies it's logged clean
  (and not killed), creates and runs the EICAR test file and verifies
  it's detected and killed, then unloads. Needs root (insmod/rmmod):
  ```bash
  sudo tests/test_detection.sh
  ```

Run `test_detection.sh` from a fresh snapshot when testing anything that
touches `handler_pre`/`av_work_fn` — same caution as manual testing.
Both scripts print a pass/fail count and exit non-zero on any failure,
so they're suitable for a pre-commit or pre-tag check even without CI
runtime support.

## Testing signature detection safely

Use the EICAR antivirus test file — a standard, harmless 68-byte string every
real AV vendor uses for exactly this purpose. It is not malware; it just has
a hash you can add to your signature list.

```bash
# create it
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
chmod +x /tmp/eicar.com
sha256sum /tmp/eicar.com
```

As of v0.2.0, the module seeds the EICAR SHA-256 signature automatically
at load time — no manual step needed. Check it's there:

```bash
cd userspace/avctl && make
./avctl list
```

Then trigger it:

```bash
/tmp/eicar.com
dmesg | tail -5     # DETECTED ... - killing
```

To manage signatures manually:

```bash
./avctl add sha256 <hex> "some-name"
./avctl del sha256 <hex>
./avctl list
```

## Testing the kernel↔daemon YARA path (v0.3.0)

`avd` loads every `*.yar`/`*.yara` file from `rules/` at startup and
scans each file that doesn't already match a kernel-side signature.
`rules/test.yar` includes a rule for the EICAR string, deliberately
separate from the SHA-256 signature already in `av/main.c` — this lets
you test the YARA path independently.

```bash
# build everything
cd av && make && cd ..
cd userspace/avd && make && cd ../..

# load the module first
sudo insmod av/av.ko
dmesg | tail -3   # "loaded, N signature(s) active"

# start the daemon (separate terminal, or backgrounded) - run from the
# repo root so it finds ./rules by default, or pass a path explicitly:
sudo userspace/avd/avd rules
```

You should see:
```
avd: loaded rules from rules/test.yar
avd: registered with kernel module (family id N), listening...
```

**Clean-file check** — run something that isn't a known signature and
doesn't match either YARA rule:

```bash
ls
```

Expect in `avd`'s output: `avd: scan request reqid=1 ...`, no `MATCH`
line. In `dmesg`: `... clean (daemon)`.

**YARA detection check** — since the EICAR file's SHA-256 is already a
kernel-side signature, temporarily remove it so the request actually
reaches the daemon and exercises the YARA path (rather than being
caught earlier by the hash check):

```bash
cd userspace/avctl && make && cd ../..
./userspace/avctl/avctl del sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
chmod +x /tmp/eicar.com
/tmp/eicar.com
```

Expect in `avd`'s output:
```
avd: MATCH "/tmp/eicar.com" -> rule "EICAR_Test_String"
```

And in `dmesg`:
```
kernel-av: DETECTED "/tmp/eicar.com" via daemon, rule "EICAR_Test_String" (pid ...) - killing
```

If `avd` isn't running, the same file should still log clean via the
fail-open path — check for the `(no daemon verdict, err=...)` suffix
(`-ENOTCONN` if `avd` never registered, `-ETIMEDOUT` if it registered
but didn't reply in time).

**What's actually been verified vs. what hasn't**: the kernel module
(including `netlink_chan.c`) was compile/link-checked against real (if
version-adjacent) kernel headers; `avd` was compile-checked against
real libnl and libyara headers; `rules/test.yar` was verified to
compile and correctly match the EICAR file using both the real `yara`
CLI and an isolated test harness running the exact scan/callback
pattern `avd.c` uses. **What has NOT been verified**: the kernel
module and `avd` have not yet been loaded and exercised together
against a real running kernel. Treat your first VM test run as a real
test, not a formality — watch `dmesg` closely, and have a snapshot
ready per the usual caution with new kprobe/workqueue-adjacent code
paths.

## Testing the API heuristics (v0.4.0)

These rules use YARA's `elf` module to check the dynamic symbol table
directly rather than doing raw string matching — more precise (only
fires on genuine imports, not the name appearing anywhere in the
file), but every individual rule is still a weak, high-false-positive
signal. Read the confidence notes in `rules/heuristics.yar` before
trusting any single match.

Quick standalone check (no kernel module needed — this exercises the
YARA rule logic in isolation):

```bash
cat > /tmp/ptrace_test.c << 'EOF'
#include <sys/ptrace.h>
#include <stddef.h>
int main(void) { ptrace(PTRACE_ATTACH, 1234, NULL, NULL); return 0; }
EOF
gcc -o /tmp/ptrace_test /tmp/ptrace_test.c

yara rules/heuristics.yar /tmp/ptrace_test
# expect: Imports_Ptrace /tmp/ptrace_test

yara rules/heuristics.yar /bin/ls
# expect: no output (clean binaries shouldn't match)
```

Full round trip through the kernel + daemon works the same way as the
YARA testing section above — `avd` loads every `*.yar` file in `rules/`
automatically, so `heuristics.yar` is active as soon as you restart
`avd`, no separate wiring needed. Running the compiled `/tmp/ptrace_test`
binary should produce a `MATCH` line in `avd`'s output listing
`Imports_Ptrace`, and a `DETECTED ... via daemon` kill in `dmesg`.

**Expect false positives.** Legitimate tools that use `ptrace` (like
`strace` or a debugger) or `memfd_create` (some package managers,
`systemd`) will also match. This is worth demonstrating deliberately in
your report — run `strace` itself through `insmod`'d module and show
it gets flagged, then discuss why single-heuristic detection isn't
production-ready without the later milestones (entropy, fuzzy hashing,
behavioral correlation) to corroborate.

## Testing the ELF structural analysis (v0.5.0)

Unlike `heuristics.yar`'s import checks, these were verified against a
**genuinely packed binary**, not just a synthetic test case:

```bash
sudo apt-get install -y upx-ucl   # or: sudo pacman -S upx

gcc -o /tmp/ptrace_test /tmp/ptrace_test.c  # from the v0.4.0 section above
upx --best -o /tmp/upx_packed /tmp/ptrace_test

yara rules/elf_analysis.yar /tmp/upx_packed
# expect: No_Section_Headers AND Entry_Point_Outside_Text
# (UPX strips section headers entirely, which is why both fire for the
#  same underlying reason - no .text section exists to check against)

yara rules/elf_analysis.yar /bin/ls
# expect: no output (clean binaries shouldn't match)
```

For the executable-stack rule specifically:

```bash
gcc -z execstack -o /tmp/execstack_test /tmp/ptrace_test.c
yara rules/elf_analysis.yar /tmp/execstack_test
# expect: Executable_Stack
```

`Has_RWX_Segment` is logically sound (checks `PT_LOAD` segments for both
`PF_W` and `PF_X`) but wasn't verified against a real sample — producing
a genuine RWX `PT_LOAD` segment needs a deliberately crafted binary or
linker script, which is a reasonable thing to build as a follow-up test
case for your report (framed as "how would I verify a detector I can't
easily produce a positive sample for").

Full round trip: same as before — `avd` loads all `*.yar` files in
`rules/` automatically, so restart `avd` after adding this file and the
new rules are active immediately.

## Testing the entropy analysis (v0.6.0)

The 7.0 threshold was picked by actually measuring entropy across real
samples, not guessed:

```bash
python3 -c "
import math, collections
def entropy(path):
    data = open(path,'rb').read()
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())
print('ls:', entropy('/bin/ls'))               # ~5.9
"
```

Whole-file check, using the same UPX-packed binary from v0.5.0:

```bash
head -c 100000 /dev/urandom > /tmp/random_sample.bin

yara rules/entropy.yar /tmp/upx_packed
# expect: High_Overall_Entropy

yara rules/entropy.yar /tmp/random_sample.bin
# expect: High_Overall_Entropy

yara rules/entropy.yar /bin/ls
# expect: no output (normal compiled code isn't high-entropy)
```

Per-section check — since UPX in default mode strips section headers
entirely (so there's nothing for this rule to check), a real positive
sample needs a binary that *keeps* sections but hides high-entropy
content in one. `objcopy` can simulate this cleanly:

```bash
cp /tmp/ptrace_test /tmp/section_entropy_test
objcopy --add-section .packed_data=/tmp/random_sample.bin \
        --set-section-flags .packed_data=alloc,contents \
        /tmp/section_entropy_test

yara rules/entropy.yar /tmp/section_entropy_test
# expect: High_Entropy_Section
```

Worth including in your report: these two rules are deliberately
complementary rather than redundant — `High_Overall_Entropy` catches
packers that strip sections (like UPX), `High_Entropy_Section` would
catch ones that don't. Neither alone covers both cases.

## Toolchain support (GCC / Clang)



A kernel module generally must be built with the same compiler family as
the target kernel — this matters if you're testing against a Clang-built
kernel (e.g. CachyOS's `-clang` variant), especially under LTO/CFI
configs. Rather than maintaining separate branches (which would mean
manually porting every fix to both), the Makefiles take `CC`/`LLVM`
overrides that get passed straight through to the kernel build system:

```bash
make                    # default: GCC
make CC=clang LLVM=1    # build against a Clang-built kernel
```

CI builds and tests both toolchains against all three kernel versions (6
matrix legs total) — see the `toolchain` matrix dimension in
`build-matrix.yml`.

## CI

`.github/workflows/build-matrix.yml` compile-tests `av/` (and the
`experiments/` modules) against three kernel versions (currently 6.12.96
LTS, 6.18.21 LTS, 7.1.4 stable — bump these as kernel.org publishes new
point releases) on every push.

**This is compile-only, not runtime testing.** GitHub-hosted runners can't
boot a different host kernel, and free-tier runners have inconsistent
`/dev/kvm` access, so a true "insmod this on kernel X and confirm it
detects EICAR" test needs a QEMU-boot job (or a self-hosted runner with
guaranteed KVM) — not implemented yet, but a good later addition once
detection logic is stable enough to be worth testing end-to-end. What this
CI *does* catch: API breakage across kernel versions (e.g. the
`proc_ops`/`file_operations` split, syscall wrapper argument layout
changes) — exactly the version-fragility risk called out above.
