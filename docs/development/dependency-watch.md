# Dependency Watch

Status tracking for all dependencies. Current as of **phylax 1.3.1**
(2026-11-04, cyrius 6.7.18). The stdlib table below predates 1.2.5 in places;
the External Dependencies table and the Toolchain section are current.

## Cyrius Stdlib Modules (31)

Opt-in via `[deps] stdlib` in `cyrius.cyml` — stdlib modules are **not**
auto-resolved; an undeclared-but-referenced symbol compiles to a `ud2`
under cyrius 6.1.x and SIGILLs at runtime. **As of cyrius 6.2.x** a
declared module is only auto-associated when *first-party source*
references it — a symbol referenced only inside a dep bundle (e.g.
sigil's `cbank` → `thread_local_*`) is not pulled by the declaration
alone and must be explicitly `include`d. See `thread_local` below.

| Module | Purpose |
|--------|---------|
| `string` | C string utilities (strlen, streq, memcpy) |
| `fmt` | Number formatting (fmt_int, fmt_hex) |
| `alloc` | Heap allocator (bump + arena) |
| `vec` | Dynamic vectors |
| `str` | Str type (fat pointer: data+len) |
| `syscalls` | Linux syscall bindings |
| `io` | File I/O (open, read, write, close) |
| `args` | Command-line arguments |
| `assert` | Testing assertions |
| `hashmap` | Hash table (open addressing, FNV-1a) |
| `regex` | Pattern matching |
| `fs` | Filesystem operations |
| `net` | TCP/UDP sockets |
| `tagged` | Option/Result types |
| `fnptr` | Function pointers |
| `callback` | Closure patterns |
| `thread` | Thread creation via clone(2) |
| `bench` | Benchmarking primitives |
| `bounds` | Boundary checking |
| `math` | f64 builtins |
| `process` | Process management |
| `chrono` | Time/date operations |
| `freelist` | Free-list allocator |
| `http` | HTTP client |
| `mmap` | Memory mapping |
| `ct` | Constant-time primitives (sigil 3.x PQ + AES-GCM surface) |
| `keccak` | SHA-3 / SHAKE / Keccak-f1600 (sigil ML-DSA) |
| `random` | getrandom for keygen / nonces (sigil) |
| `slice` | Slice subscripts (`_slice_idx_get_W`; sigil 3.7.x via agnosys) |
| `thread_local` | Thread-local storage (sigil `cbank` crypto cache). **Explicitly `include`d in `src/lib.cyr` + `src/lib_core.cyr`** — under cyrius 6.2.x the `[deps] stdlib` declaration alone no longer pulls it (only sigil's bundle references it; no first-party caller), so the declaration is kept (so `cyrius deps` stages the file) and the explicit include defines the symbols. |
| `bayan` | Data-format bundle (cyrius 6.1.25 carve) — json / toml / csv / base64 / bigint / cyml / u128, canonical `bayan_*` + legacy aliases |

> **The bayan carve (cyrius 6.1.25).** `json`, `toml`, `csv`, `base64`,
> `bigint` (+ `cyml`, `u128`) were removed from cyrius stdlib and folded
> into the single `bayan` sibling bundle. Those names no longer resolve
> standalone — **declaring `bayan` supplies all of them**, and phylax's
> existing `json_*` / `toml_*` / `base64_*` / `csv_*` / `bigint` call
> sites keep working through bayan's back-compat aliases. Replacing the
> five carved modules with `bayan` is roughly size-neutral (the DCE
> binary actually shrank 1.98 MB → 1.78 MB); it also resolves the
> `bayan_json_get` symbol the sigil bundle references.

## External Dependencies

| Dependency | Version | Purpose | Notes |
|-----------|---------|---------|-------|
| `sakshi` | 2.5.10 | Structured logging | **Folded stdlib module** as of 1.2.5 — declared in `[deps] stdlib`, not a git dep. Tracks the toolchain fold (6.7.18 vendors 2.5.10). |
| `sigil` | 3.13.15 | Cryptographic primitives | **Folded stdlib module** as of 1.2.5. SHA-256 (SHA-NI dispatch); only `sha256` consumed. 6.7.18 vendors 3.13.15 — the same version libro 2.11.3 pins as a git dep. |
| `majra` | 2.13.0 | Pubsub/counter | **Vestigial** — staged + DCE-pruned. Latest release; = bote 3.8.6's own majra pin. |
| `bote` | 3.8.6 | MCP tool registry/dispatch | **`dist/bote-core.cyr`** transport-free bundle; latest release (3.8.6 refuses duplicate JSON keys). bote-core is 673 fns (306 at 3.4.10; phylax calls a handful) — harmless on x86 since cyrius 6.7.14 removed the compaction cap, but it grows the uncompacted aarch64 binary. ⚠ **C-string API:** tool names/descriptions/handler keys are cstrs, an inputSchema is a ToolSchema object (`tool_schema_from_json`), a handler gets raw JSON text and returns a JSON cstr; its requires block names only `hashmap sys` since 3.8.x. |
| `libro` | 2.11.3 | Belt-and-suspenders pin | Latest release; = bote 3.8.6's transitive libro. Not referenced by phylax (DCE-pruned). Pulls patra 1.16.6. |

### Folded modules: why the declaration shape matters

`sakshi` and `sigil` moved from `[deps.X]` git blocks into `[deps] stdlib` at 1.2.5, because the
6.5.x toolchain snapshot vendors both. This is not cosmetic:

- `cyrius distlib` classifies a **git dep** out of the *stdlib leaves*, so a folded module declared
  that way is omitted from `dist/phylax.deps` / `dist/phylax-core.deps` entirely. A consumer
  provisioning strictly from a sidecar then links with `sha256_*` / `sakshi_*` undefined. Verified:
  phylax's sidecars carried **one** leaf (`thread_local`) before the move and 32 / 15 after.
- A git dep **overlays** the snapshot, so a pin that lags the fold silently *downgrades* the module
  for every build.

⚠ Do not re-add git blocks for these two. The `cyrius` pin is the only knob that moves them.

Comments inside the `stdlib` array were parsed, not skipped, through cyrius 6.6.16: a `[` inside
one ended the array (entries below it vanished — this dropped `sakshi`/`sigil` from the sidecars on
the first 1.2.5 attempt, with no error and a green build), and a `"quoted phrase"` was collected as a
module name. **cyrius 6.6.17 (m6) fixed both**; measured at 1.2.8, a comment naming a bracketed
section and quoting a phrase inside the array leaves `lib/` unchanged. Rationale still goes below the
closing `]` by convention.

**From 6.6.18 the sidecars are compile-verified, not unioned.** `dist/phylax.deps` went 34 → 5 leaves
and `dist/phylax-core.deps` 22 → 4 at 1.2.8; the folded leaves reach a consumer through phylax's git
deps' own requires blocks. Verified with scratch consumers of both bundles (x86_64 + aarch64).

### ⚠ No `path =` lines on git deps

Through cyrius 6.6.x a `path` beside `git`/`tag` **won** whenever the sibling checkout existed: the
resolver vendored the sibling's working tree, skipped the commit-pin check, and an implicit resolve
(`cyrius build`) rewrote `cyrius.lock`. CI has no siblings, so it built the tag. Measured at 1.2.8
(`../bote` at an untagged 3.8.5 was vendored, failed to compile, and rewrote the lock). **cyrius 6.7.6
(pinned since 1.3.0) makes `path` a local-mode-only override** (`CYRIUS_LOCAL=1` / `--local`: resolves
into `build/local-deps/lib/`, leaves `lib/` and the lock alone, names the sibling's commit and dirty
state). phylax still commits none.

### Lock checks: `cyrius deps --locked`, before anything writes the lock

`cyrius deps` writes `cyrius.lock` — since 6.6.9 it adds missing rows — so `deps` followed by
`deps --verify` repairs the lock it was supposed to audit (measured at 1.3.0: delete a row, and that
sequence passes). `cyrius deps --locked` (6.7.6) resolves the tags, compares them with the committed
lock (and, if `lib/` exists, every vendored file's bytes), writes nothing, and exits 1 on any
difference. CI and release run it first, vendor, then run it again.

### Known dep-shape cost — RESOLVED (cyrius 6.6.11)

libro declares sigil as a git dep (`src/sha256.cyr`, `src/hex.cyr`, `src/sha_ni.cyr`,
`dist/sigil-mldsa.cyr`). Through cyrius 6.6.10 that staged `lib/sigil_*.cyr` **alongside** the folded
`lib/sigil.cyr` — inert duplicates, but ~350 KB of DCE binary at 1.2.5 and 232 duplicate-fn warnings
per build at 1.2.7. 6.6.11 (S2) stops vendoring a git dep's thin sigil files when `sigil` is a stdlib
leaf. At 1.2.8 the leaves are gone, the lock is 65 files (was 67), the warnings are 0, and the binary
is 866,640 B (915,728 B for the same tree on 6.6.2). The vestigial `[deps.majra]` / `[deps.libro]`
blocks remain a dep-pruning candidate on their own merits.

## Toolchain

- **Cyrius**: 6.7.18 (pinned in `cyrius.cyml`)
- **bayan 1.11.1 (folded at 6.7.18) types its keys** (`: cstring` / `: Str`) and the compiler
  now flags a Str passed where a cstring is declared. That exposed phylax's Str-keyed `toml_get`
  calls, which had never matched. Use the `_by_cstr` / `_by_str` forms; the legacy aliases are
  `#deprecated`. bayan 1.11.1 also includes the stdlib `unicode` family (+7 lock files).
- **aarch64 has no DCE compaction** ("no compaction repair model yet"): the aarch64 binary carries
  every dep's dead code (3.29 MB at 1.3.1 vs 0.91 MB x86).
- **⚠ DCE compaction cap, cyrius < 6.7.14 (historical since 1.3.1).** `CYRIUS_DCE=1` declines to compact past 4,096
  dead-code runs ("compaction declined … the repair registry cap") and leaves the NOPed bytes in
  the binary. phylax crossed it at 1.3.0 via bote-core 3.4.10 (4,048 → 4,105 dead fns; 866 KB →
  2.36 MB). Fixed upstream in 6.7.14 (IN-4). Watch for the note on every dep bump.
- **Per-target constants come from the stdlib.** A phylax global named like a stdlib `SYS_*` / `O_*`
  enum member wins program-wide (inside stdlib wrappers too). On aarch64 that broke inotify
  (`-ENOSYS`) and `O_NOFOLLOW` until 1.3.0. The aarch64 backend's ESYSXLAT rewrites only a fixed
  table of raw x86 numbers and passes the rest through verbatim. The x86 arch macro is
  `CYRIUS_ARCH_X86`, not `CYRIUS_ARCH_X86_64`.
- **6.7.2: array sizes accept const expressions** (`var statbuf[STAT_BUFSZ]`). **6.7.6: mabda
  declares `const F64_255`** — any same-named phylax global would be a consumer hard error.
- **6.6.18 `distlib` compile-verifies on six targets** (incl. aarch64) and refuses — exit 1,
  "sidecar NOT written" — after rewriting the bundle body. A leaf a bundled module needs only on
  another target must be an explicit `include` in that module (`lib/math.cyr` in
  `src/analyze.cyr`, for `f64_log2` on aarch64). CI gates on `cyrius distlib --check`; never
  `distlib || true`.
- **6.6.20 stamps a bundle's `# Version:` from the manifest**, so `cyrius.cyml` must keep
  `version = "${file:VERSION}"` (CI refuses a literal).
- **6.6.9 added `net_resolve_ipv4`** — `sock_connect` takes a packed IPv4, never a host string.
- **6.6.9 changed how bench `min`/`max` are picked** (`avg` unchanged) — compare `avg` across it.
- **Cyrius octal is `0o`-prefixed**; a C-style leading zero is decimal (`0100000` = 100000). This
  hid a 64 KiB read bug from 0.9 to 1.2.8.
- **6.5.28 `cyrius fmt` rewrites files IN PLACE** (breaking). stdout is now a
  one-line report, not the formatted source, so the old
  `diff <(cyrius fmt "$f") "$f"` CI idiom is broken two ways: the bare call
  reformats the checkout it is auditing, and the diff compares a report against
  every source file. `--dry` reports without writing but does not restore a
  pipeable stream. **Use `cyrius fmt --check`** — it exits non-zero and names
  the first differing `file:line`. The same release fixed `--check` itself
  (it was silent on clean files in 5.10.x) and made the formatter paren-aware,
  which reformatted 63 lines across 10 files at the 1.2.5 sweep.
- **6.5.19 rewrote the benchmark harness.** `bench_run` auto-batches and
  subtracts a *measured* timer floor (~1.34 µs/clock read on the dev box);
  before, it wrapped a clock pair around every iteration. **Bench rows are not
  comparable across this boundary** without subtracting one floor from the
  older side. See the 1.2.5 CHANGELOG for the reconciled table.
- **6.5.x refuses to emit a binary with reachable undefined functions**, which
  converts the old `ud2`-then-SIGILL-at-runtime failure into a build error.
- **6.4.65 thread-local slot allocator** — `lib/thread_local.cyr` gained
  `thread_local_alloc()` (allocator ≥ slot 16; frozen 0-15 for legacy
  hardcoded slots) and grew TLOCAL_MAX_SLOTS 16 → 128. sigil 3.12.1's
  crypto-bank now claims its slot from the allocator instead of the
  hardcoded slot 8, so phylax's `sha256` path requires cyrius ≥ 6.4.65.
  Lands transparently through the `include "lib/thread_local.cyr"` opt-in
  phylax already carries — no source change.
- **6.3.32** made `sync.cyr` the sole owner of `mutex_*` (folded into
  `thread.cyr`), retiring the three `duplicate fn 'mutex_*'` build
  warnings phylax emitted since the `atomic`+`sync` additions in 1.2.2.
- **6.1.26 ganita carve — confirmed no-op for phylax.** matrix/linalg +
  the advanced transcendentals (sinh/cosh/pow/asin/atan2/hypot/fibonacci/
  binomial) were carved to the `ganita` sibling, but stdlib `math` keeps
  the primitives — including the `f64_log2` polyfill phylax's
  `shannon_entropy` uses. phylax touches no carved fn, so **no `ganita`
  dep** is needed; `math` stays in `[deps] stdlib`.
- **6.1.27** raised the binary output cap 2 MB → 16 MB (relocated
  `output_buf` to the heap top, 8× larger). phylax's non-DCE test
  binaries (~2 MB with the bayan bundle) now have ample headroom.

## Upgrade Notes

- `lib/` is a **derived artifact** (gitignored). The dep contract is
  `cyrius.cyml` + `cyrius.lock`; `cyrius deps` rehydrates `lib/` against
  the pinned toolchain snapshot (stdlib, incl. `bayan`) plus the pinned
  git bundles. After a toolchain pin bump, a clean rehydration is
  `rm -rf lib && cyrius deps` (this is what CI/Release now do) — a stale
  `lib/` shadows the snapshot and breaks resolution when stdlib modules
  move (as the bayan carve did).
- Dep tag bumps in `cyrius.cyml` must point to a GitHub-released tag,
  never a local repo's in-progress `VERSION`.
