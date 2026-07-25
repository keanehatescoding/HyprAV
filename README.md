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
av/                  - the actual antivirus module (single, evolving)
  av.c
  signatures.h
  Makefile
experiments/          - throwaway learning modules, not tagged/released
  hello/              - minimal LKM: module_init/module_exit, dmesg logging
  procfs_demo/        - /proc entry you can read/write from userspace
  kprobe_log/         - kprobe on execve that just logs filenames (no blocking)
```

## Releases

Milestones are marked with annotated git tags on `av/`, not separate
directories. Suggested progression:

| Tag      | What it adds                                              |
|----------|------------------------------------------------------------|
| `v0.1.0` | kprobe execve hook + in-kernel SHA-256 + hardcoded signature list, kill on match |
| `v0.2.0` | signature DB moved to a kernel hashtable, populated from userspace via `/proc` or `debugfs` |
| `v0.3.0` | behavioral heuristics (rapid file writes, sensitive path writes, self-deleting binaries) |
| `v0.4.0` | fuzzy hashing via a userspace daemon |
| `v1.0.0` | quarantine policy, structured logging, performance benchmarks |

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

## Testing signature detection safely

Use the EICAR antivirus test file — a standard, harmless 68-byte string every
real AV vendor uses for exactly this purpose. It is not malware; it just has
a hash you can add to your signature list.

```bash
# create it
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
chmod +x /tmp/eicar.com
sha256sum /tmp/eicar.com   # add this hash to signatures.h
```

Then try to execute it (`/tmp/eicar.com`) and confirm your module logs a
detection and kills it before it runs.

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
