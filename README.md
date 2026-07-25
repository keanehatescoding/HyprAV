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
av/                  - the actual antivirus module (single, evolving)
  main.c              - kprobe hook, workqueue, multi-algorithm hashing
  sigtable.c/.h       - kernel hashtable signature store + /proc interface
  Makefile
userspace/
  avctl/              - CLI for managing the signature DB via /proc
    avctl.c
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
| `v0.3.0` | YARA rule scanning | userspace daemon (libyara), kernel forwards flagged paths, daemon returns a verdict |
| `v0.4.0` | String & API heuristics (suspicious imported symbols — `ptrace`, `memfd_create`, ELF symbol table scanning) | userspace |
| `v0.5.0` | ELF header & section analysis (suspicious section names, RWX-permission sections, anomalous entry points) | userspace |
| `v0.6.0` | Entropy analysis (Shannon entropy per section — packed/encrypted binary detection) | userspace |
| `v0.7.0` | Fuzzy hashing (ssdeep/TLSH) against a known-sample corpus | userspace |
| `v0.8.0` | Behavioral heuristics (rapid file writes, sensitive path writes, self-deleting binaries) | kernel (workqueue-deferred, same pattern as v0.1.0) |
| `v0.9.0` | Evasion resistance — adversarial testing against your own engine (packing, obfuscation, timing-based sandbox detection) and documenting what does/doesn't get caught | test suite + report, not shipped code |
| `v1.0.0` | Quarantine policy, structured logging, performance benchmarks | kernel + userspace |

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
