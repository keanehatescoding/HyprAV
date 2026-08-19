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
packaging/
  avd.service          - systemd unit for running avd persistently -
                        see "Running avd persistently" below
av/                  - the actual antivirus module (single, evolving)
  main.c              - kprobe hooks (execve, openat, unlink, unlinkat,
                        rename, renameat, renameat2), workqueue,
                        multi-algorithm hashing
  sigtable.c/.h       - kernel hashtable signature store + /proc interface
  netlink_chan.c/.h   - Generic Netlink channel to avd (see docs/netlink-protocol.md)
  netlink_proto.h     - protocol definitions shared with userspace/avd
  behavior.c/.h        - v0.8.0: behavioral heuristics (rapid write-intent
                        opens, sensitive path writes/deletes, self-deleting
                        binaries) - per-PID state, mutex-protected. Excludes
                        /sys, /proc, /dev, .cache dirs, and SQLite
                        -journal/-wal/-shm files from counting - each
                        exclusion added after a real false-positive kill,
                        see the incident writeups in the testing section.
                        Also: a runtime-managed trusted-binary-hash list
                        (/proc/kernel_av_trusted, via `avctl trust`) that
                        exempts the rapid-write counter specifically for
                        vouched-for binaries - added after path-pattern
                        exclusions alone proved to be whack-a-mole
  Makefile
rules/
  test.yar             - sample YARA rules used for testing avd (EICAR string
                        match, a toy reverse-shell pattern) - weight=100,
                        override=true on both: explicit test fixtures meant
                        to definitively trigger, not weak corroborating signals
  heuristics.yar        - v0.4.0: API import heuristics using YARA's elf
                        module (ptrace, memfd_create, mprotect, dlopen,
                        plus a compound rule) - individually weak signals
                        (weight 5-40); real testing killed zsh/sh/uwsm
                        before weighted scoring existed - see v0.9.1 below
  elf_analysis.yar      - v0.5.0: ELF structural analysis (no section
                        headers, executable stack, RWX segments, entry
                        point outside .text). No_Section_Headers and
                        Executable_Stack carry override=true (convict
                        alone, verified clean against real samples);
                        Entry_Point_Outside_Text does NOT (confirmed
                        false positive on uwsm in real testing)
  entropy.yar           - v0.6.0: whole-file and per-section Shannon
                        entropy - threshold (7.0/8.0) calibrated against
                        real samples, catches packers that strip AND
                        packers that keep section headers
corpus/
  fuzzy_hashes.txt      - v0.7.0: corpus of known-bad ssdeep fuzzy hashes
                        (format: hash,name) - the seed entry is a test
                        fixture, not real malware; add real sample hashes
                        here once testing against actual threats
userspace/
  avctl/              - CLI for managing the signature DB (/proc/
                        kernel_av_signatures) and the trusted-process
                        list (/proc/kernel_av_trusted, `avctl trust
                        add/del/list`) - see the storage-metadata
                        incident in the behavioral heuristics testing
                        section for why the trust list exists. Both
                        are in-memory kernel hashtables with no
                        persistence of their own - `avctl save <file>`/
                        `avctl load <file>` dump/replay both across an
                        rmmod+insmod cycle.
    avctl.c
    Makefile
  avd/                - daemon: receives scan requests over netlink, loads
                        rules/*.yar and corpus/fuzzy_hashes.txt at startup;
                        replies with a verdict based on weighted YARA
                        scoring (or an override-tier rule alone), then
                        (on a miss) fuzzy-hash similarity. v1.0.0:
                        quarantines the file on any MALICIOUS verdict
                        (moves to /var/lib/av-quarantine/, chmod 0000)
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
  benchmark.sh          - v1.0.0: execve/openat hook overhead, module
                        loaded vs unloaded (needs root, real numbers only
                        from your VM - see the benchmarking section)
  evasion/              - v0.9.0: adversarial tests against the engine itself
    test_dynamic_symbol_evasion.sh    - standalone, no kernel module needed
    test_fuzzy_evasion.sh              - standalone
    test_entropy_dilution_evasion.sh   - standalone
    test_slow_drip_evasion.sh          - needs the live kernel module (VM only)
  qemu-boot/             - the QEMU-boot CI job's actual runtime test
    init.c                 - static PID 1: insmod av.ko, exec a clean
                            file and an EICAR file, check dmesg - see
                            .github/workflows/qemu-boot-test.yml
    cold_launcher.c         - dedicated regression case for the
                            cold-pathname bypass documented below and
                            in av/main.c's handler_pre() comment
```

See `docs/evasion-findings.md` for the full writeup of what each test
found — this is the actual report deliverable for v0.9.0, not just the
scripts.

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
| `v0.7.0` ✅ | Fuzzy hashing (ssdeep/libfuzzy) against a corpus of known-bad hashes — catches near-identical variants that evade exact hash matching entirely; verified: a modified variant scores 100 similarity, an unrelated file scores 0 | `avd` + `corpus/fuzzy_hashes.txt` |
| `v0.8.0` ✅ | Behavioral heuristics — rapid write-intent opens (ransomware-like), sensitive path writes/deletes, self-deleting binaries; hooks `openat`/`unlink`/`unlinkat` instead of `write()` to avoid risky cross-process fd→path resolution | kernel (workqueue-deferred, same pattern as v0.1.0) |
| `v0.9.0` ✅ | Evasion resistance — 4 techniques tested against the real engine (dynamic symbol resolution, fuzzy-hash dilution, entropy dilution, slow-drip behavioral pacing); 3 of 4 evaded their target layer, but one (entropy dilution) was still caught by structural analysis running alongside it — the core validation of the layered-detection design | `tests/evasion/` + `docs/evasion-findings.md` |
| `v0.9.1` ✅ | Weighted YARA scoring — real testing killed `/usr/bin/zsh`, `/bin/sh`, and `uwsm` (legitimate binaries matching a single low-confidence rule each); conviction now requires matched rules' `weight` meta to sum past `MALICIOUS_SCORE_THRESHOLD` (100), with a below-threshold match falling through to fuzzy-hash corroboration instead of returning clean outright | `avd` + `weight` meta on every rule |
| `v1.0.0` ✅ | Override tier (a small set of verified-clean rules convict alone regardless of score — added after discovering v0.9.1's scoring change silently broke the v0.9.0 entropy-dilution defense-in-depth finding), quarantine (userspace, `avd`-driven detections only), structured `key=value` kernel logging, performance benchmark harness | kernel + userspace |

**Scope note on quarantine**: only detections that go through `avd`
(YARA, API heuristics, ELF analysis, entropy, fuzzy hash) get their
file quarantined (moved + `chmod 0000`). Kernel-only detections (exact
signature match, behavioral heuristics) still only kill the process —
doing file rename/unlink from kernel space needs `vfs_rename()`/
`vfs_unlink()`, genuinely risky and version-fragile kernel API
territory (the same category of problem the netlink `genl_family`
layout caused earlier in this project). Userspace `rename()`/`chmod()`
carries none of that risk, so quarantine lives in `avd` instead of
`main.c`.

`v0.3.0-prep` is worth tagging on its own once verified — see
`docs/netlink-protocol.md` for the full protocol design, including a
documented fail-open-on-timeout decision worth discussing in your report.

**Scope note on v0.7.0**: only ssdeep (via libfuzzy) was implemented,
not TLSH. Both are valid fuzzy-hashing approaches with different
tradeoffs (ssdeep is simpler and widely supported; TLSH is generally
considered more robust for larger files) — worth mentioning as a
deliberate scope decision in your report, and a reasonable stretch
goal if you have time later (`libtlsh-dev` is available and would sit
alongside the ssdeep check with essentially the same corpus-comparison
structure).

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

## Running `avd` persistently

The testing sections further down (`Testing the kernel↔daemon YARA
path` etc.) run `avd` by hand in a foreground terminal, which is the
right way to develop against it but not to actually run it day to day
— it doesn't survive a logout, a crash, or a reboot that way.
`userspace/avd/Makefile` has an `install` target for that:

```bash
cd userspace/avd
make
sudo make install     # binary -> /usr/local/bin/avd
                       # unit   -> /usr/lib/systemd/system/avd.service
                       # rules/corpus -> /etc/hyprav/
sudo systemctl daemon-reload
sudo systemctl enable --now avd.service
sudo journalctl -u avd -f  # avd's stdout/stderr, same output as running it by hand
```

`journalctl` needs `sudo` (or membership in the `systemd-journal` group)
to read another user's unit logs on most distros' default journald
config - plain `journalctl -u avd` run as your own user will typically
just come back empty or permission-denied rather than showing avd's
output, since the unit runs as `root`.

`install` does **not** enable or start the service itself — reviewing
`packaging/avd.service` before enabling anything that scans and
quarantines files with root privileges is worth the extra step. The
unit runs `avd` as root with no sandboxing (`ProtectSystem=`,
`DynamicUser=`, etc. would break it — see the unit's own comments):
`avd`'s whole job is reading arbitrary files anywhere on the system
and moving malicious ones into quarantine, which is fundamentally
privileged, system-wide work.

The `av` kernel module itself still has no systemd unit — `insmod` is
a manual, documented step (see Building above), so there's nothing to
order `avd.service` against. `avd` fails fast with a clear error if
the module isn't loaded yet (can't resolve the `av_genl` netlink
family); the unit's `Restart=on-failure` with no burst limit means
systemd just keeps retrying on a fixed backoff until the module shows
up, rather than requiring precise unit ordering against something it
doesn't manage.

Override the install paths the usual GNU way if you're packaging this
for a distro instead of installing directly:

```bash
sudo make install PREFIX=/usr DESTDIR=/tmp/pkgroot
```

`PREFIX` (default `/usr/local`) and `SYSCONFDIR` (default `/etc/hyprav`)
control where files actually end up at runtime - `avd.service` is a
template (`@BINDIR@`/`@SYSCONFDIR@` placeholders in
`packaging/avd.service`) that `make install` renders against them, so
`ExecStart` in the installed unit always matches wherever `avd` was
actually installed:

```
ExecStart=<PREFIX>/bin/avd <SYSCONFDIR>/rules <SYSCONFDIR>/fuzzy_hashes.txt /var/lib/av-quarantine
```

e.g. `PREFIX=/usr` above renders `ExecStart=/usr/bin/avd ...`, not
`/usr/local/bin/avd`. `DESTDIR` is different from both of these - it's
only a *staging root* prepended to every installed path for this one
`make install` invocation (so a packaging script can assemble a tree
under `/tmp/pkgroot` before archiving it), not part of where `avd`
actually runs once installed. It is deliberately **not** substituted
into `ExecStart`: an `avd.service` built with `DESTDIR=/tmp/pkgroot`
still points at `<PREFIX>/bin/avd`, the real path once the staged tree
is deployed to `/`, not `/tmp/pkgroot/<PREFIX>/bin/avd`.

There's also a fourth override, `UNITDIR` (default
`/usr/lib/systemd/system`) - where the *rendered* `avd.service` file
itself gets installed, i.e. where systemd will actually find it. It
doesn't appear in `ExecStart` and doesn't need to match `PREFIX`; it
exists because some distros expect systemd unit files under
`/lib/systemd/system` instead (a packaging convention difference, not
a `PREFIX`-derived path), so a packager can point it there without
otherwise changing where `avd` itself installs to:

```bash
sudo make install PREFIX=/usr UNITDIR=/lib/systemd/system DESTDIR=/tmp/pkgroot
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
line. In `dmesg`: `kernel-av: event=clean type=daemon path="/usr/bin/ls" ...`.

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

Expect in `avd`'s output (as of `v0.9.1`+, matches include the
aggregate score and whether an override rule fired — `test.yar`'s
`EICAR_Test_String` carries `override = true`, so it convicts on its
own regardless of the numeric score):
```
avd: MATCH "/tmp/eicar.com" -> 1 rule(s), score=100, override=1: "EICAR_Test_String"
```

And in `dmesg` (structured `key=value` format as of `v1.0.0`):
```
kernel-av: event=detected action=kill type=daemon path="/tmp/eicar.com" reason="daemon:EICAR_Test_String" pid=...
```

If `avd` isn't running, the same file should still log clean via the
fail-open path — check for `type=fail-open` in the `dmesg` line
(`err=-ENOTCONN`-style errno if `avd` never registered, `err=-ETIMEDOUT`
if it registered but didn't reply in time).

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

For `Has_RWX_Segment` (checks `PT_LOAD` segments for both `PF_W` and
`PF_X`) — producing a genuine RWX `PT_LOAD` segment isn't as simple as
a compiler flag, but GNU `ld`'s old `-N`/`--omagic` option (merge
text+data into one segment, historically used for a.out-style
binaries) still does it on a modern ELF freestanding binary, and `ld`
itself warns when it does:

```bash
cat > /tmp/rwx_start.c <<'EOF'
void _start(void) {
    __asm__ volatile ("mov $60, %rax\n xor %rdi, %rdi\n syscall\n");
}
EOF
gcc -nostdlib -static -no-pie -Wl,-N -o /tmp/rwx_test /tmp/rwx_start.c
# expect a linker warning: "... has a LOAD segment with RWX permissions"
readelf -l /tmp/rwx_test | grep RWE   # confirms it end-to-end, not just trusting the warning

yara rules/elf_analysis.yar /tmp/rwx_test
# expect: Has_RWX_Segment (also Entry_Point_Outside_Text, an artifact
# of this being a minimal freestanding binary - not RWX-related)

# negative controls - same rule, real binaries, no match expected
# (yara only takes one target per invocation):
for b in /bin/ls /bin/bash /usr/bin/gcc /usr/bin/python3; do
    yara rules/elf_analysis.yar "$b"
done

# and the same test program WITHOUT -Wl,-N, to isolate that the
# RWX match really is about omagic specifically:
gcc -nostdlib -static -no-pie -o /tmp/rwx_control /tmp/rwx_start.c
yara rules/elf_analysis.yar /tmp/rwx_control   # no Has_RWX_Segment
```

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

## Testing fuzzy hashing (v0.7.0)

This is the one detection layer that genuinely does something the
others can't: catch a file that's been slightly modified specifically
to dodge exact hash matching. Demonstrate it directly:

```bash
sudo apt-get install -y ssdeep   # or: sudo pacman -S ssdeep

# the corpus already contains the fuzzy hash of /tmp/ptrace_test (built
# in the v0.4.0 section) - verify the seed hash still matches your build:
ssdeep -b /tmp/ptrace_test

# make a "variant" - same binary, a few bytes appended (simulating a
# minor recompile/modification that would produce a COMPLETELY
# different SHA-256, but should still fuzzy-match)
cp /tmp/ptrace_test /tmp/ptrace_test_variant
echo "extra padding" >> /tmp/ptrace_test_variant

ssdeep -b /tmp/ptrace_test > /tmp/corpus_hash.txt
ssdeep -m /tmp/corpus_hash.txt /tmp/ptrace_test_variant
# expect: matches with a high score (100 in testing)

ssdeep -m /tmp/corpus_hash.txt /bin/ls
# expect: no output (unrelated file, no match)
```

Full round trip through `avd` (fuzzy matching only runs on a YARA
miss, so use a file that doesn't already trigger `heuristics.yar` or
`elf_analysis.yar` — the variant above works since it's a normal,
unpacked binary):

```bash
sudo insmod av/av.ko
cd userspace/avd && make && cd ../..
sudo userspace/avd/avd rules corpus/fuzzy_hashes.txt

# in another terminal
/tmp/ptrace_test_variant
```

Expect in `avd`'s output:
```
avd: FUZZY MATCH "/tmp/ptrace_test_variant" -> "test-ptrace-sample" score=100
```

And in `dmesg`:
```
kernel-av: DETECTED "/tmp/ptrace_test_variant" via daemon, rule "Fuzzy:test-ptrace-sample(100)" (pid ...) - killing
```

**The threshold (60/100) is a starting point, not a tuned value** — it
was picked because it sits well above the "unrelated files" baseline
(0 in testing) and well below the "genuine minor variant" case (100),
but real-world tuning needs an actual malware corpus with known
variant families, which is out of scope here. Worth discussing this
gap explicitly in your report rather than presenting 60 as validated.

## Testing behavioral heuristics (v0.8.0)

Three separate things to verify - rebuild and reload first:

```bash
cd av && make clean && make && cd ..
sudo rmmod av 2>/dev/null
sudo insmod av.ko
dmesg -C
```

**Self-delete detection** — a process that deletes its own executable:

```bash
cp /bin/true /tmp/selfdel_test
/tmp/selfdel_test &   # runs and exits almost immediately, not useful alone
# better: use a script that deletes itself while "running"
cat > /tmp/selfdel_test.sh << 'EOF'
#!/bin/bash
rm -- "$0"
sleep 2
EOF
chmod +x /tmp/selfdel_test.sh
/tmp/selfdel_test.sh &
sleep 1
dmesg | tail -5
# expect: DETECTED behavioral: self-deleting binary ... - killing
```

**Sensitive path write/delete** — writing to a path containing `.ssh`:

```bash
mkdir -p /tmp/fake_home/.ssh
echo test > /tmp/fake_home/.ssh/id_rsa_test
dmesg | tail -5
# expect: DETECTED behavioral: write-intent open of sensitive path ...
```

**Rapid file modification** — touching more than `WRITE_OPEN_THRESHOLD`
(50) files within the 2-second window:

```bash
mkdir -p /tmp/rapid_test && cd /tmp/rapid_test
for i in $(seq 1 55); do echo "x" > "file_$i.txt"; done
cd - && dmesg | tail -10
# expect: DETECTED behavioral: rapid file modification ... - killing
# (the killed process is your shell's `for` loop subshell context -
#  expect the loop to terminate abruptly partway through)
```

### Incident: this heuristic tried to kill PID 1 on first real-VM test

Worth documenting in full, not glossing over — this is exactly the
kind of finding a report should include. On first boot with the
module loaded, real system activity (not a synthetic test) produced:

```
kernel-av: DETECTED behavioral: rapid file modification (possible
ransomware pattern) "/sys/fs/cgroup/system.slice/systemd-logind.service/
pids.max" (pid 1) - killing
```

**Root cause**: `systemd` (PID 1) routinely writes to many cgroup
control files (`pids.max`, `memory.max`, etc.) as normal service
management — nothing malicious about it. The original threshold (20
opens/2s) had no concept of "this is a kernel control-plane path, not
user data," so it counted cgroup writes the same as it would count a
ransomware process encrypting documents in `/home`. A separate false
positive fired on `/dev/tty1`/`/dev/tty2` for the same underlying
reason — terminal I/O isn't file modification in any meaningful sense
either.

**Two fixes, both necessary, not just one:**
1. **Root cause**: paths under `/sys/`, `/proc/`, and `/dev/` are now
   excluded entirely from both the rapid-write counter and the
   sensitive-path check — this is what actually stops the false
   positives from happening in the first place.
2. **Hard safety net, independent of the above**: `PID 1` can never be
   killed by this module, under any circumstance, regardless of which
   heuristic fires or how confident it is. This isn't a substitute for
   fix #1 — a heuristic that's *correctly* triggered against a real
   threat that happened to be running as PID 1 (implausible, but not
   provably impossible) still shouldn't be allowed to bring down the
   whole system. Defense in depth: don't rely on any single layer
   being bug-free when the failure mode is "the kernel panics."

The fact that the test system apparently kept running afterward
suggests the target may have been a namespaced "PID 1" inside a
sandboxed systemd service (systemd's `PrivatePIDs`-style isolation
gives some services their own PID namespace) rather than true host
init — but this was never verified with certainty, and the fix
doesn't depend on knowing which case it was. Treat "we got lucky" and
"we fixed it" as two different, non-substitutable things.

### Incident: browser storage engine killed as "rapid file modification"

[#incident-browser-storage-engine-killed-as-rapid-file-modification](#incident-browser-storage-engine-killed-as-rapid-file-modification)

A second real false positive, same heuristic, different root cause —
worth documenting on its own rather than folding into the PID 1 fix
above, since the fix is a different mechanism entirely.

```
kernel-av: DETECTED behavioral: rapid file modification (possible
ransomware pattern) "/home/keane/.zen/<profile>/storage/default/
moz-extension+++<uuid>/.metadata-v2" (pid 87527) - killing
```

**Root cause**: Zen (a Firefox fork)'s storage engine rewrites a
handful of its own small IndexedDB/metadata files repeatedly as part
of completely normal browsing activity, easily exceeding 50 write
opens in a 2-second window. Unlike the PID 1 case, this isn't a path
that should be excluded wholesale — `~/.zen/.../storage/` is user
data, and a heuristic that special-cased every browser's profile
directory would be pure whack-a-mole (the next legitimate multi-file
writer — a database engine, an IDE's autosave, `git`, a package
manager — would just trip it from a different path next time).

**The actual fix**: the counter now tracks *distinct paths* written
in the window, not raw `openat()` call count. A dedup ring buffer
(sized to `WRITE_OPEN_THRESHOLD`, so it can never overflow before the
threshold itself would fire) tracks path hashes seen so far in the
current window; repeat opens of an already-seen path no longer
increment the counter. A process rewriting the same few files
hundreds of times a second no longer trips this heuristic, while a
process touching 50+ *distinct* files in the same window — the actual
ransomware pattern — still does. This is a strictly better
approximation of "mass file modification" than raw open count ever
was, independent of the false positive that surfaced it.

**Other caveats worth discussing in your report:**
- `WRITE_OPEN_THRESHOLD` (50 *distinct paths*/2s, after the fix above)
  is still a tunable guess, not derived from real ransomware sample
  behavior — legitimate tools that touch many distinct files fast
  (extracting an archive, `git clean` across many files, a fresh
  `npm install`) can plausibly still trigger false positives, since
  distinct-path counting doesn't help when the files genuinely are
  distinct. Worth actually testing and tuning further based on what
  you find. The `/sys`, `/proc`, `/dev` exclusion and the distinct-path
  dedup remove the two false positives found in testing so far, but
  neither claims to make this heuristic false-positive-free.


- Per-PID behavioral state is now reclaimed by a periodic GC sweep
  (`behavior_gc_fn`, every `GC_INTERVAL_MS` = 30s) rather than
  accumulating for the module's lifetime — added after this was
  originally documented as a known gap. Liveness is checked via
  `find_vpid()` + `pid_task(..., PIDTYPE_TGID)` rather than hooking
  process exit directly, deliberately avoiding the same class of
  thread-group-teardown-timing kernel API fragility this project has
  been bitten by elsewhere (see the netlink `genl_family` history).
  The 30s interval is a starting point, not a tuned value — worth
  measuring actual memory growth under sustained load if you want a
  number for your report rather than just "it gets cleaned up
  eventually."
- `openat` is the only open-family syscall hooked - `open()` (without
  `at`) and `creat()` are separate syscalls on some architectures/libc
  versions and could evade this specific hook. Modern glibc routes
  through `openat` internally on Linux, so this covers the common
  case, but a determined evasion attempt might not.

### Incident: cache directories and SQLite journal files

The caveat above wasn't hypothetical — it predicted exactly what
happened next. A third real false positive, same heuristic, same
browser, but a genuinely different root cause from either fix above:

```
kernel-av: event=detected action=kill type=behavioral
path="/home/keane/.cache/zen/<profile>/cache2/entries/8A56562BBBFACFFB09AAEFC7CEE620713C94D995"
reason="rapid file modification (possible ransomware pattern)" pid=1921

kernel-av: event=detected action=kill type=behavioral
path="/home/keane/.zen/<profile>/permissions.sqlite-journal"
reason="rapid file modification (possible ransomware pattern)" pid=120852
```

**Root cause**: unlike the previous incident (a handful of files
rewritten *repeatedly*), this is genuinely many *distinct* files —
exactly the case the distinct-path dedup fix explicitly does not help
with. A browser like Zen/Firefox keeps many independent SQLite
databases (permissions, bounce-tracking-protection, places, cookies,
favicons...), and every transaction commit creates and deletes a
`-journal` (or `-wal`) file as a normal SQLite implementation detail.
Combined with `~/.cache/`'s cache2 entries (browsers routinely write
dozens of small cache files per page load), legitimate startup/browsing
activity comfortably clears 50 distinct paths in 2 seconds.

**The fix**: two new, narrow exclusions, same spirit as `/sys`/`/proc`/
`/dev` but for a structurally different reason — these paths are
excluded not because they're kernel control-plane interfaces, but
because their entire *purpose* is disposable/regenerable data that
ransomware has no reason to target:
- **`/.cache/` substring match** (not prefix — matches
  `/home/<user>/.cache/...` for any user) — cache directories are
  explicitly meant to be safely deletable; there's essentially no
  legitimate reason ransomware would encrypt cache data specifically.
- **`-journal`/`-wal`/`-shm` suffix match** — SQLite's own transient
  transaction-implementation files, not user content.

Verified against the exact paths from this incident (all three
correctly excluded) and against normal target paths like
`~/Documents/report.docx`, `~/Downloads/file.exe`, and `/etc/passwd`
(all correctly still counted/flagged) — the fix doesn't quietly widen
into "ignore anything under the home directory."

**What this does NOT cover** (an honest gap, not silently glossed
over): other applications' cache-like directories that don't use the
`.cache` name specifically — e.g. some Chromium-based apps use
`~/.config/<app>/Cache` outside the XDG `.cache` convention. If you
hit a fourth false positive from one of those, the same substring-match
pattern extends cleanly; it just hasn't been needed yet.

### Incident: per-origin storage metadata, and stepping back from whack-a-mole

A fourth real false positive, same heuristic, same browser:

```
kernel-av: event=detected action=kill type=behavioral
path="/home/keane/.zen/<profile>/storage/default/https+++accounts.youtube.com^userContextId=6/.metadata-v2"
reason="rapid file modification (possible ransomware pattern)" pid=188612
```

This one is structurally different from all three fixes above: it's
neither a repeated file (already deduped), nor under `/.cache/`, nor
`-journal`/`-wal`/`-shm` suffixed. It's a **new distinct path per
website origin visited** — Firefox/Zen creates a `storage/default/
<origin>/` directory per site, each with its own `.metadata-v2` file.
Browse enough tabs in a burst and that's 50+ distinct paths again,
under yet another naming convention the previous fixes don't cover.

**Why this one didn't get its own path-pattern exclusion**: patching
this specific pattern would almost certainly just delay a fifth one —
IndexedDB files, Cache API storage, service worker data, whatever
Firefox touches next. Four fixes in, chasing individual naming
conventions stopped looking like "closing gaps" and started looking
like an unwinnable, open-ended list. The code already predicted this
outcome in an earlier comment (see the incident above this one) before
it happened.

**The actual fix: exempt the process, not the path.** A small,
runtime-managed trusted-binary list (keyed by **SHA-256 hash, not
path** — a path-based allowlist is trivially spoofable by naming
malware `zen-bin` and dropping it in the expected directory; a hash
isn't) exempts the rapid-write *counter specifically* for vouched-for
binaries. Everything else — signature matching, YARA/heuristics,
entropy, fuzzy hashing, the sensitive-path check, self-delete detection
— still fully applies to a trusted binary. This only ever suppresses
one volume-based signal, and only for an exact, cryptographically
identified binary, never a name or location.

```bash
cd userspace/avctl && make && cd ../..
sha256sum /opt/zen-browser-bin/zen-bin
./userspace/avctl/avctl trust add <hash> "Zen Browser"
./userspace/avctl/avctl trust list
./userspace/avctl/avctl trust del <hash>
```

**Why this over the alternatives** (raising the threshold, or
redesigning the signal around file-extension diversity): raising the
threshold weakens detection against *every* process, not just
browsers — a real attacker just needs to stay under whatever the new
number is. A smarter signal (extension diversity, entropy-of-writes)
is a genuinely better long-term answer but a much bigger lift than
this project's scope justified once four real incidents made the
tradeoff concrete. Trusted-process exemption is also the standard
real-world EDR pattern for exactly this problem (publisher/hash
allowlisting) — not a workaround invented for this project.

**Persistence: `avctl save`/`avctl load`.** Both `/proc/kernel_av_signatures`
and `/proc/kernel_av_trusted` are in-memory kernel hashtables — everything
in them vanishes on `rmmod`, and the module only ever auto-seeds the one
EICAR test signature at `insmod` time. `avctl save <file>` dumps both the
signature DB and the trust list into a single file as replayable
write-commands; `avctl load <file>` replays them (an entry that already
exists, e.g. the auto-seeded EICAR signature on a fresh load, is reported
as skipped rather than an error):

```bash
./userspace/avctl/avctl save /etc/kernel-av/state.txt
sudo rmmod av && sudo insmod av/av.ko
./userspace/avctl/avctl load /etc/kernel-av/state.txt
```

## Testing evasion resistance (v0.9.0)

Full findings are in `docs/evasion-findings.md` — this section is just
how to reproduce them.

```bash
# three of these run standalone, no kernel module needed:
tests/evasion/test_dynamic_symbol_evasion.sh
tests/evasion/test_fuzzy_evasion.sh
tests/evasion/test_entropy_dilution_evasion.sh

# this one needs the live module and root - re-verified live against
# a real dmesg capture as of v0.9.0's follow-up (see
# docs/evasion-findings.md's finding #4 for the confirmed result):
sudo insmod av/av.ko
sudo tests/evasion/test_slow_drip_evasion.sh
```

The headline result worth understanding before anything else: **3 of
4 techniques evaded their specific target layer, but the layering
itself held** — evading `entropy.yar` on a padded, packed binary did
not evade `elf_analysis.yar` running against the same file. That's the
central validation of treating detection as several independent
checks rather than one big score, and the strongest single piece of
evidence for that design choice in the whole project.

## Testing weighted scoring and the override tier (v0.9.1 / v1.0.0)

Confirm the false-positive fix actually holds, and that the override
tier didn't reintroduce the problem it was meant to fix:

```bash
# single weak import only - must NOT convict (the zsh/sh/uwsm case)
cat > /tmp/ptrace_only.c << 'EOF'
#include <sys/ptrace.h>
#include <stddef.h>
int main(void) { ptrace(PTRACE_ATTACH, 1234, NULL, NULL); return 0; }
EOF
gcc -o /tmp/ptrace_only /tmp/ptrace_only.c
/tmp/ptrace_only
dmesg | tail -3
# expect: event=clean (or no daemon match logged as MALICIOUS) -
#         Imports_Ptrace alone (weight 15) stays well under threshold

# a real UPX-packed binary - must still convict (multiple weights sum,
# or No_Section_Headers' override fires alone either way)
upx --best -o /tmp/upx_test /tmp/ptrace_only
/tmp/upx_test
dmesg | tail -3
# expect: event=detected ... reason="daemon:No_Section_Headers,..."
```

If you have `tests/evasion/test_entropy_dilution_evasion.sh` results
from before the override tier existed, re-running it now is the most
direct way to see the fix — the padded/diluted sample should convict
again where it previously evaded (see `docs/evasion-findings.md`
finding #3 for the full before/after story).

## Testing quarantine, structured logs, and benchmarks (v1.0.0)

**Quarantine** — trigger any `avd`-driven detection (the EICAR-via-
daemon flow above works, or the UPX test just above):

```bash
ls -la /var/lib/av-quarantine/
# expect: a file named <timestamp>_<original-basename>.quarantined
#         with permissions ----------  (chmod 0000)
```

Confirm the original file is gone from its original location, and that
the quarantined copy genuinely can't be read/executed even as root
without an explicit `chmod` back first.

**TOCTOU protection**: between `avd` scanning a file and actually
quarantining it, there's a window where something with write access to
a parent directory could swap the path for a symlink pointing
elsewhere — `quarantine_file()` would then act on the wrong file.
`handle_scan_request()` now opens the file **once**, at the very
start, before scanning even begins, and every step after that
(YARA scan, fuzzy-hash check, and the eventual quarantine) reads
through that same fd rather than re-resolving the path string — an
open fd keeps referring to the exact file it was opened against for
its entire lifetime, regardless of anything that happens to the path
afterward.

That closes the window for *what content ends up quarantined*
specifically: `quarantine_file()` creates the quarantine copy via
`linkat(fd, "", AT_FDCWD, dest, AT_EMPTY_PATH)`, which links a new
directory entry to `fd`'s underlying inode directly rather than
walking `path` again, so it's immune to a same-directory swap
regardless of what the swap points at. (A plain `rename()` through
`/proc/self/fd/N` looks like it should do the same thing and was tried
first - it doesn't: verified empirically, it always fails with `EXDEV`
on this kernel, since the source is treated as living on procfs itself
for the cross-device check rather than transparently resolving to the
real filesystem. `linkat()` + `AT_EMPTY_PATH` is the primitive that
actually targets the fd's real inode.) `linkat()` can still fail for
reasons that have nothing to do with a swap - `EXDEV` if the
quarantine directory is on a different filesystem (hardlinks can't
cross filesystems), or `ENOENT` if the file's link count already hit
zero (an `unlink()`-then-replace race, as opposed to a
`rename()`-away one - `linkat()` can't resurrect a fully unlinked
inode even though the fd remains perfectly valid). Either failure
falls back to copying the fd's content directly, which is just as
immune to the swap.

What `linkat()`/the copy fallback do NOT cover is removing the
*original* from its old location afterward - `unlink()` has no
fd-based equivalent, so that one step still has to re-walk `path`,
regardless of which of the two methods above created the quarantine
copy. It gets an identity re-check (`fstat()` on the fd vs. a fresh
`lstat()` on the path) immediately before it fires, and refuses on a
mismatch, logging `possible symlink swap` - this is
risk-reduction, not elimination, for this one narrowed step, the same
kind of tradeoff as before, but a failure here now only means the
original wasn't also cleaned up from its old location, never that the
wrong content got quarantined (which the earlier, wholly path-based
design could still get wrong even with its own re-check, via the
lstat/rename gap or a same-inode double-swap).

Worth demonstrating deliberately for your report: swap `/tmp/eicar.com`
for a symlink to something else immediately after triggering detection
but before `avd` would normally quarantine it, and confirm the
*original* scanned content still ends up quarantined (compare its
contents/hash against what `/tmp/eicar.com` originally held) rather
than whatever the symlink now points at - regardless of whether the
swap used `rename()` (leaves the original's link count > 0, `linkat()`
succeeds) or `unlink()`+`symlink()` (drops it to 0, `linkat()` falls
back to the copy) the quarantined content should be correct either
way. You should also see the `possible symlink swap` refusal in
`avd`'s output either way, since the final unlink of the now-swapped
path always re-checks first.

**Structured logs** — every detection/clean/suppressed event is now a
single grep/awk-parseable line:

```bash
dmesg | grep 'kernel-av: event='
# event=detected action=kill type=signature path="..." reason="..." pid=N
# event=clean type=daemon path="..." pid=N md5=... sha1=... sha256=...
# event=suppressed action=none type=behavioral path="..." reason="..." pid=1
```

**Performance benchmark**:

```bash
sudo tests/benchmark.sh
```

Report both the raw baseline numbers AND the loaded-vs-unloaded
delta/ratio. Two scenarios worth benchmarking separately, since they
measure different things:

- **`avd` not running**: `av_netlink_scan_request()` returns
  `-ENOTCONN` immediately (no daemon registered → no wait at all) —
  this measures just the kernel-side hashing + signature lookup cost.
- **`avd` running** (`sudo userspace/avd/avd rules corpus/fuzzy_hashes.txt`
  in another terminal first): this additionally measures the netlink
  round trip and `avd`'s own scan time (YARA + fuzzy hash) for every
  execve that misses the kernel-side signature check — the more
  realistic end-to-end number, and the one worth reporting as the
  "real" overhead.

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

Two tiers, both on every push, both across the same three kernel
versions (currently 6.12.96 LTS, 6.18.21 LTS, 7.1.4 stable — bump
these as kernel.org publishes new point releases):

**Tier 1 - `.github/workflows/build-matrix.yml`**: compile-tests
`av/` (and the `experiments/` modules) against gcc and clang. Catches
API breakage across kernel versions (e.g. the `proc_ops`/
`file_operations` split, syscall wrapper argument layout changes) -
exactly the version-fragility risk called out above. Compile-only,
not runtime testing - GitHub-hosted runners can't boot a different
host kernel, so this can't confirm the module actually *works* on
each version, only that it builds.

**Tier 2 - `.github/workflows/qemu-boot-test.yml`**: actually boots
each kernel version in QEMU and confirms real runtime detection -
`insmod av.ko`, exec a clean file (must NOT be killed), exec an EICAR
file (must be killed, with the structured `event=detected` line
present in `dmesg`). No busybox, no shell: `tests/qemu-boot/init.c`
is a small statically-linked C program that runs as PID 1, loads the
module directly via `init_module(2)`, and drives both checks itself.
Falls back to TCG (software emulation) when `/dev/kvm` isn't usable,
since free-tier runners have inconsistent KVM access - both paths are
exercised and confirmed to work identically.

This tier found a real gap during development: `av.ko`'s kprobe hook
copies the exec target's pathname via `strncpy_from_user()` in atomic
(kprobe) context, which can't sleep to fault in a userspace page that
isn't resident yet - unlike the kernel's own later, in-process copy of
the same pointer during `execve()`'s normal handling, which can. This
is not a narrow timing race that needs a well-positioned attacker: any
process whose exec pathname argument has never been touched before -
e.g. a freshly execve()'d static binary that does nothing but exec a
literal path - hits it deterministically. A real shell essentially
never does, since by the time anything calls `execve()` its own memory
has had far too much prior activity for a relevant page to still be
cold, but a minimal launcher doesn't need to work hard to trigger it on
purpose.

`tests/qemu-boot/init.c` exercises the common case (it touches the
pathname before exec'ing, so detection works as intended there), while
`tests/qemu-boot/cold_launcher.c` is a separate, minimal binary kept
deliberately untouched-on-exec, specifically to reproduce this gap on
every CI run instead of letting it go unverified. Its result doesn't
gate the job's PASS/FAIL - either outcome is informative - but it's
printed to the serial log every run. See `handler_pre()`'s comment in
`av/main.c` for the full account, including three fix directions
considered and rejected (deferring the copy to workqueue context,
failing closed on `-EFAULT`, and switching to an LSM hook) - documented
as a known, tracked limitation (same risk-reduction-not-elimination
category as this file's other TOCTOU notes), not fixed as part of
adding this test.
