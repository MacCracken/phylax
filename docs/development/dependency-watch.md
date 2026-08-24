# Dependency Watch

Status tracking for all dependencies. Current as of **phylax 1.2.1**
(2026-06-17).

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
| `sakshi` | 2.4.11 | Structured logging | **Folded stdlib module** as of 1.2.5 — declared in `[deps] stdlib`, not a git dep. Tracks the toolchain fold. |
| `sigil` | 3.12.9 | Cryptographic primitives | **Folded stdlib module** as of 1.2.5 — declared in `[deps] stdlib`, not a git dep. SHA-256 (SHA-NI dispatch); only `sha256` consumed. 6.5.35 vendors exactly 3.12.9. |
| `majra` | 2.7.0 | Pubsub/counter | **Vestigial** — bote-core dropped `events_majra`, so nothing references it; staged + DCE-pruned. Aligned to bote 3.3.7's transitive majra. |
| `bote` | 3.3.7 | MCP tool registry/dispatch | **`dist/bote-core.cyr`** transport-free bundle; the 11 hand-picked `src/*.cyr` modules no longer link under bote 3.x (dispatch pulls new `prompts`/`resources`). 3.3.6 grew the core profile 11 → 12 modules (`content.cyr`). |
| `libro` | 2.8.12 | Belt-and-suspenders pin | Aligned to bote 3.3.7's transitive libro; not referenced by phylax or bote-core (DCE-pruned). ⚠ Pulls sigil as a *git* dep, staging granular `lib/sigil_*.cyr` beside the folded monolith — see "Known dep-shape cost" below. |

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

⚠ Comments inside the `stdlib` array are parsed, not skipped. A `[` inside one **ends the array**
(entries below it silently vanish — this dropped `sakshi`/`sigil` from the sidecars on the first
attempt, with no error and a green build), and a `"quoted phrase"` inside one is **collected as a
module name**. Keep rationale below the closing `]`.

### Known dep-shape cost

libro 2.8.12 declares sigil as a git dep (`src/sha256.cyr`, `src/hex.cyr`, `src/sha_ni.cyr`,
`dist/sigil-mldsa.cyr`), which stages those leaves as `lib/sigil_*.cyr` **alongside** the folded
`lib/sigil.cyr`. Both are 3.12.9, so the duplicate `sha256_hex` / `sha512_hex` / `hex_decode_into`
definitions are behaviourally inert, but they cost ~350 KB of DCE binary (2,207,520 → 2,562,016 B at
the 1.2.5 sweep). Dropping phylax's own `[deps.majra]` / `[deps.libro]` blocks does **not** avoid it
— measured, the pull survives transitively via bote 3.3.7, phylax loses version control, and a
*larger* majra bundle is staged (locked files 65 → 79). The fix belongs upstream in libro.

## Toolchain

- **Cyrius**: 6.5.35 (pinned in `cyrius.cyml`)
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
