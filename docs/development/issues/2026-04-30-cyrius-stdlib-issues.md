# Cyrius stdlib gaps surfaced during the phylax 1.1.0 final pass

**Status**: open. None of these block the phylax 1.1.0 release on
x86_64 Linux. The first one (`f64_log2`) blocks aarch64 cross-builds
hard; the rest are advisories or worked around inside phylax with
local backfill.

**Filed for**: cyrius-side hygiene. Phylax's CI marks the aarch64
cross-build `continue-on-error: true` so the rest of the gates green
while these remain open. Any cyrius release that closes any of these
is a candidate for a follow-up phylax pin nudge.

## Environment

| Layer            | Version / id                                                         |
|------------------|----------------------------------------------------------------------|
| Build host       | x86_64 Linux (Arch), Cyrius 5.7.48                                   |
| Toolchain        | `~/.cyrius/versions/5.7.48/{bin,lib}` (canonical install via install.sh) |
| Phylax           | 1.1.0 @ `main` (working-tree change set queued for the 1.1.0 tag)    |
| Sigil dep        | 2.9.5 (transitively pulls agnosys 1.0.4 via `lib/agnosys.cyr` bundle)|
| Cross-build host | not run on hardware this session — issues are static / cc5_aarch64-side |

---

## 1. `f64_log2` is x86-only — blocks aarch64 cross-build of phylax

### Symptom

```sh
$ cyrius build --aarch64 src/main.cyr build/phylax-aarch64
…
warning:33664: duplicate fn 'hex_encode' (last definition wins)
warning:33683: duplicate fn 'hex_decode' (last definition wins)
warning:33723: duplicate fn 'str_contains' (last definition wins)
error:33828: f64_log2 is x86-only for v5.6.0; aarch64 has no native log2 — needs polyfi[ll]
FAIL
```

The `f64_log2` builtin (compiler intrinsic, not a library function —
no source-level `fn f64_log2` exists in `~/.cyrius/versions/5.7.48/lib/math.cyr`)
emits the equivalent of `vfpclassPD` / `getexp` directly on x86_64.
On aarch64 there is no single-instruction equivalent; the toolchain
errors out at codegen time rather than emitting a wrong instruction.

### Phylax-side blast radius

Single call site:

```
src/analyze.cyr:31:            var log2p = f64_log2(p);
src/analyze.cyr:32:            var term = f64_mul(p, log2p);
```

This is inside `shannon_entropy(data, len)` — Shannon entropy is
load-bearing for every entropy-based detection in the YARA / strings
/ analyze pipeline. We can't ship phylax aarch64 with this call
stubbed to a constant.

The DCE pass does not prune `shannon_entropy` because it's reachable
from the public scan pipeline (via `analyze_buffer` → severity / category
heuristics). Tested with `CYRIUS_DCE=1 cyrius build --aarch64 src/main.cyr` —
same error.

### Workarounds considered

1. **stdlib polyfill** *(preferred — what we want from cyrius)*. Add
   a software `f64_log2(x)` in `lib/math.cyr` (or a new `lib/math_log.cyr`)
   that uses bit-extract on the f64 representation: pull the IEEE-754
   exponent, normalize the mantissa to `[1, 2)`, and approximate
   `log2(m)` via a small polynomial or lookup. Consumers see the
   builtin name; per-arch dispatch lives in stdlib.
2. **Phylax-side fixed-point integer entropy.** Rewrite `shannon_entropy`
   to compute `H = log2(N) − (Σ c[v] · log2(c[v])) / N` over integer
   counts, with `log2(c)` precomputed as fixed-point for `c = 1..N`.
   Doable but invasive — touches the entropy benchmark numbers, the
   chi-squared correlation in `analyze.cyr`, and a couple of YARA
   condition evaluators that compare against entropy thresholds.
3. **Phylax-side f64 polyfill.** Same algorithm as (1), but parked in
   `src/analyze_polyfill.cyr` and gated with `#ifdef CYRIUS_ARCH_AARCH64`.
   Bridges the gap until (1) lands.

We've taken neither for 1.1.0. CI's aarch64 step is `continue-on-error: true`
with a comment pointing at this issue.

---

## 2. `sys_stat` / `sys_fstat` wrapper asymmetry between x86_64 and aarch64 stdlib peers

### Symptom

`lib/syscalls_aarch64_linux.cyr` exposes:

```cyrius
fn sys_stat(path, buf) {
    return syscall(SYS_NEWFSTATAT, AT_FDCWD, path, buf, 0);
}
fn sys_fstat(fd, buf) {
    return syscall(SYS_FSTAT, fd, buf);
}
```

`lib/syscalls_x86_64_linux.cyr` exposes the `SYS_STAT = 4` /
`SYS_FSTAT = 5` enum members but **no wrapper functions**. Direct
audit:

```sh
$ grep -E "^fn sys_stat|^fn sys_fstat" \
    ~/.cyrius/versions/5.7.48/lib/syscalls_x86_64_linux.cyr
# (no output)
$ grep -E "^fn sys_stat|^fn sys_fstat" \
    ~/.cyrius/versions/5.7.48/lib/syscalls_aarch64_linux.cyr
fn sys_stat(path, buf) {
fn sys_fstat(fd, buf) {
```

A consumer that calls `sys_stat(path, buf)` portably (relying on the
aarch64 wrapper to dispatch through the at-family) hits an
`undefined function 'sys_stat' (will crash at runtime)` warning on
x86_64 builds. Same for `sys_fstat`.

### Phylax-side workaround (shipped in 1.1.0)

`src/syscall_x86_64_linux.cyr` self-gated peer file:

```cyrius
#ifdef CYRIUS_ARCH_X86

fn sys_stat(path, buf) {
    return syscall(SYS_STAT, path, buf);
}

fn sys_fstat(fd, buf) {
    return syscall(SYS_FSTAT, fd, buf);
}

#endif
```

`src/syscall_aarch64_linux.cyr` is intentionally empty (stdlib already
has the wrappers on this arch). Both files are self-gated with
`#ifdef CYRIUS_ARCH_X86 / AARCH64` so they ship in `dist/phylax.cyr`
side-by-side without colliding. Same pattern agnosys 1.0.4 uses for
its arch-conditional syscall numbers.

### What we want from cyrius

Backfill `sys_stat` / `sys_fstat` wrappers in
`lib/syscalls_x86_64_linux.cyr` to match the aarch64 surface. Once
that lands, phylax (and agnosys's `src/fuse.cyr`, which calls
`sys_stat` directly) can drop the local backfill in a follow-up.

---

## 3. Pre-existing `cc5_aarch64` `_SC_ARITY` false-positives on
   stdlib at-family wrappers

### Symptom

Building a 4-line stdlib-only program for aarch64 emits 9
`syscall arity mismatch` warnings:

```sh
$ cat /tmp/empty.cyr
include "lib/syscalls.cyr"
fn main() { return 0; }
var r = main();
syscall(SYS_EXIT, r);

$ cyrius build --aarch64 /tmp/empty.cyr /tmp/empty-aarch64
compile … warning:1518: syscall arity mismatch
warning:1523: syscall arity mismatch
warning:1528: syscall arity mismatch
warning:1540: syscall arity mismatch
warning:1545: syscall arity mismatch
warning:1609: syscall arity mismatch
warning:1693: syscall arity mismatch
warning:1756: syscall arity mismatch
warning:1763: syscall arity mismatch
…
```

The line numbers map to stdlib's at-family wrappers in
`lib/syscalls_aarch64_linux.cyr`: `sys_rmdir`, `sys_unlink`,
`sys_chmod`, `sys_fork`, `sys_setsid`-class call sites. The
calls' arities match Linux's `__SYSCALL` table; `_SC_ARITY` is the
one disagreeing.

### Lineage

The cyrius CHANGELOG already records two `_SC_ARITY` false-positive
fix slots in this family:

- **5.7.x** — `_SC_ARITY(112)` `SYS_SETSID` arity 1 → 0 (the wrapper
  passes 0 user args; the table mistakenly expected 1).
- **5.7.x** — Cross-arch openat sentinel false-positive
  (`syscall(SYS_OPEN, 0 - 100, path, 0, 0)` parsed as 4 args vs
  `open`'s 3 — but the dead branch on the running arch is the one
  that gets the warning).

The 9 remaining hits are presumably the same class.

### Phylax-side blast radius

`cyrius build --aarch64 src/main.cyr` in phylax shows the same 9
warnings plus 2 phylax-side warnings at preprocessed-unit lines
3477 / 3509 (likely also false-positives — every call site was
hand-verified against the aarch64 Linux `__SYSCALL` arity table).
Advisory only; binary is well-formed. Tracked here so a future cyrius
release that tightens the table can confirm phylax's clean.

### What we want from cyrius

A `_SC_ARITY` audit pass over the aarch64 table, same shape as the
prior two slots — pin each at-family wrapper's expected user-arg
arity to what the wrapper actually passes, regardless of what the
target syscall accepts.

---

## 4. Duplicate-fn warnings on aarch64 cross-build (NI-class fns)

### Symptom

The 2026-04-28 phylax handoff doc noted, deferred-from-cyrius:

> Duplicate-fn warnings on aarch64 cross-build (`aes_ni_available`,
> `_aes_ni_cpuid_probe`, `aes256_encrypt_block_ni`) — cyrius team
> couldn't reproduce in 5.7.34's investigation; deferred to
> "agnosys-side investigation when the agent has the include context."
> Once Phase 1's agnosys sweep is in flight on a dev box, capture the
> include sequence and report back.

### Sigil 2.9.5 follow-up

In phase 2 of this release chain we hit a *different* duplicate-fn
condition: a missing `[lib]` TOML section header in sigil's
`cyrius.cyml` (the `modules = [...]` table was scoped under `[build]`,
which 5.7.x's auto-deps gate treats as an auto-prepend list). That
produced 374 duplicate-fn warnings on x86_64. Closed by adding the
`[lib]` section header.

That's a different mechanism than the handoff doc's NI-class
duplicates. Sigil's NI-specific dupes (the original 3 in
`src/aes_ni.cyr` + `_aes_ni_cpuid_probe`) reappeared on the aarch64
cross-build of sigil 2.9.5 alongside ~370 others; same class as the
sigil x86_64 dupes (cyrius stdlib auto-prepend interaction with sigil's
`src/lib.cyr` chain). With sigil's `[lib]` fix the x86 path is clean;
aarch64 still shows the NI-class warnings — likely the same root
cause as the handoff doc's defer. Phylax doesn't observe NI-class
dupes directly (it pulls sigil via `dist/sigil.cyr`, which is
single-file and self-contained).

### What we want from cyrius

A repro recipe in the cyrius team's own checkout that surfaces the
NI-class dupe from a clean state. Sigil's `[lib]` fix likely changes
what the cyrius team sees; their last "couldn't reproduce" report
predates that fix.

---

## Closeout criteria

- (1) closed → drop the phylax aarch64 step's `continue-on-error: true`
  and the polyfill backstop note in `src/analyze.cyr`.
- (2) closed → delete `src/syscall_x86_64_linux.cyr`'s
  `sys_stat` / `sys_fstat` wrappers; the aarch64 peer's empty
  `#ifdef` block stays as a placeholder or is also dropped if there's
  nothing else to backfill.
- (3) closed → confirm phylax's aarch64 cross-build emits zero
  `syscall arity mismatch` warnings against an empty cyrius program;
  if it does, the residual two warnings at lines 3477 / 3509 of the
  phylax preprocessed unit are by-design phylax-side — investigate
  separately.
- (4) closed → confirm sigil 2.9.6+ aarch64 cross-build has zero
  duplicate-fn warnings; phylax inherits transitively.
