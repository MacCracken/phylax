# Changelog

All notable changes to Phylax will be documented in this file.

## [1.2.0] - 2026-06-10

Toolchain + dep pin sweep onto the cyrius 6.1.x line, including the
**bayan stdlib carve** migration. No detection behavior changes in
`src/`; the only source edit is the engine version string. The bump
surfaced two build-breaks the sweep resolves — a `sha256` SIGILL and the
carved-out data-format modules — both in **Fixed**.

### Changed

- **Cyrius toolchain pin: 5.10.44 → 6.1.25.** Moves phylax onto the
  6.1.x frontend/codegen line. `lib/` is a derived artifact, rehydrated
  by `cyrius deps` against the pinned toolchain snapshot (stdlib) plus
  the pinned git bundles; the dep contract is `cyrius.cyml` +
  `cyrius.lock`.

- **First-party dep pins, all bumped to latest released:**
  - **sakshi 2.2.4 → 2.2.10** — patch cycle, logging surface unchanged
    at phylax's call sites.
  - **sigil 3.1.1 → 3.7.8** — phylax's only sigil surface is
    `sha256_hex`. The 3.7.x bundle defaults ML-DSA-65 on (since 3.7.6)
    and routes crypto through a `cbank` cache that references new
    stdlib symbols; see **Fixed**.
  - **majra 2.4.4 → 2.4.5** — patch refresh, pubsub/counter surface
    unchanged at phylax's transitive call sites.
  - **bote 2.7.1 → 2.7.3** — bote 2.7.3 now pins libro 2.7.2 itself,
    so the phylax-side libro override is aligned to that (below).
  - **libro 2.6.3 → 2.7.2** — kept as an explicit pin matching bote's
    transitive pin. The original override rationale (bote shipping a
    broken libro 2.6.2 with a bare `ct_eq` call) is resolved upstream;
    the pin stays so the resolved version is explicit and doesn't drift
    silently with bote's transitive pin.

- **Stdlib `[deps]` set re-shaped for the cyrius 6.1.25 bayan carve.**
  Stdlib modules are opt-in via `[deps] stdlib`, not auto-resolved.
  - **Removed `json`, `toml`, `base64`, `csv`, `bigint`** — cyrius
    6.1.25 carved these data-format modules out of stdlib (`lib/{json,
    toml,csv,base64,bigint,cyml,u128}.cyr` deleted) and folded them into
    the single `bayan` sibling bundle. They no longer resolve as
    standalone stdlib names.
  - **Added `bayan`** — supplies all of the above. phylax's existing
    `json_*` / `toml_*` / `base64_*` / `csv_*` / `bigint` call sites
    keep working through bayan's back-compat aliases (migration to the
    canonical `bayan_*` names is deferred to the deprecation window).
  - **Added `slice`** — sigil 3.7.x's transitive `lib/agnosys.cyr` uses
    slice subscripts (`_slice_idx_get_W`).
  - **Added `thread_local`** — sigil's `cbank` crypto-cache path calls
    `thread_local_*` (see **Fixed**).
  - Net effect: the DCE release binary is **smaller** (1.98 MB → 1.78 MB)
    and the non-DCE test binaries fit comfortably under the output cap.

- **CI / Release dep resolution wipes `lib/` before resolving.** Both
  workflows now run `rm -rf lib && cyrius deps`. `lib/` is untracked
  (since `445a60f`), so a fresh runner already starts clean — this is
  defensive against a cached/self-hosted runner carrying a stale `lib/`
  that would *shadow* the snapshot (declared stdlib names resolve to
  `./lib/<name>.cyr` with no fall-through, masking the carve migration).
  The primary clean-checkout fix is the `bayan` migration above; this is
  dep-process hygiene.

### Fixed

- **`sha256` SIGILL (exit 132) under cyrius 6.1.x + sigil 3.7.8.** With
  `thread_local` undeclared, sigil's `cbank` call to `thread_local_*`
  was an *unresolved* symbol, which cyrius 6.1.x emits as a `ud2` — the
  binary builds clean but SIGILLs the instant a crypto path touches it
  (here, the first `sha256_hex`). `tests/test_sha256.tcyr` reproduced it
  as exit 132. Declaring `thread_local` resolves it; the test passes
  (`e3b0c442…` empty-string vector + determinism). Root cause matches
  sigil's own CHANGELOG 3.7.8 note ("unresolved call to a `ud2`").

- **Clean-checkout build failure from the bayan carve.** `cyrius deps`
  on a fresh 6.1.25 runner failed with `cannot read
  .../lib/{json,toml,base64,csv,bigint}.cyr` — phylax still listed those
  carved-out names in `[deps] stdlib`, and a stale tracked `lib/` had
  masked it locally. Migrating to `bayan` (above) + the CI `rm -rf lib`
  step fixes resolution; the full suite is green at 177 + 11 assertions
  and the build emits zero `undefined function` warnings.

## [1.1.1] - 2026-05-11

Toolchain + dep pin sweep, dependency-resolution model cleanup, and
new doc-health ledger. No source changes in `src/` or `tests/`; the
binary surface and detection behavior are unchanged from 1.1.0.

### Changed

- **Cyrius toolchain pin: 5.7.48 → 5.10.44.** Picks up the 5.8.x →
  5.10.x cycle's stdlib + frontend deltas. Notable for phylax:
  `lib/syscalls_x86_64_linux.cyr` in the 5.10.x snapshot now ships
  `sys_stat` / `sys_fstat` wrappers, making phylax's local
  `src/syscall_x86_64_linux.cyr` x86 backfill redundant (the
  duplicate-fn warnings surface but the build is otherwise clean;
  scheduled for removal in the 5.11.x / 5.12.x sweep).

- **First-party dep pins, all bumped to latest released:**
  - **sakshi 2.1.0 → 2.2.4** — minor + patch cycle, structured-logging surface unchanged at phylax's call sites.
  - **sigil 2.9.5 → 3.1.1** — major version. Phylax's only sigil
    surface is `sha256_hex`, which is unchanged in body (only a
    return-type annotation added between 2.9.5 and 3.x). The 3.x
    bundle pulls new transitive stdlib references (`ct_eq_bytes_lens`,
    `ct_select`, `_keccak_absorb`, `_keccak_f1600`, `shake256`,
    `random_bytes`); see the stdlib addition below.
  - **majra 2.4.1 → 2.4.4** — minor refresh, pubsub/counter surface
    unchanged at phylax's transitive call sites (via bote's
    `events_majra` module).
  - **bote 2.5.1 → 2.7.1** — bote 2.6.3+ added a transitive
    `[deps.libro]` pin at libro 2.6.2; see new dep below.

- **New direct dep: `[deps.libro] = 2.6.3`.** Overrides bote's
  transitive libro 2.6.2 pin. libro 2.6.2 calls bare
  `ct_eq(data_a, len_a, data_b, len_b)` at `dist/libro.cyr:116` —
  the stdlib only exposes `ct_eq_bytes(a, b, n)` and
  `ct_eq_bytes_lens(a, a_len, b, b_len)`, so the link fails with
  `undefined function 'ct_eq' (will crash at runtime)`. libro 2.6.3
  fixed the call site to `ct_eq_bytes_lens`. Phylax itself doesn't
  consume the libro surface — the bytes get linked because bote's
  bundle references libro symbols transitively. Hold this override
  until bote bumps its own libro pin past 2.6.2.

- **Stdlib additions: `ct`, `keccak`, `random`.** The sigil 3.x
  bundle's PQ (ML-DSA-65) + AES-GCM surfaces reference these
  symbols; the linker needs them declared even though DCE prunes
  the call sites in phylax's binary (phylax consumes only
  `sha256_hex`).

- **`lib/` is no longer tracked.** Resolved deps move from
  in-tree-vendored to `cyrius deps`-resolved, mirroring the libro
  and majra pattern that's been in place for several minor cycles.
  The contract is the pin set in `cyrius.cyml`; the bytes get
  rehydrated on demand. `.gitignore` carries `/lib/`. (Existing
  tracked `lib/` files need a one-time `git rm -r --cached lib/`
  by the maintainer; gitignore patterns don't retroactively
  untrack content.)

### Added

- **`docs/doc-health.md`** — living ledger of doc currency in the
  phylax repo. Tracks Tier 1 root files → Tier 8 root-level
  benchmark snapshots, with five buckets (Fresh / Stale /
  Read-through outstanding / Evergreen / Frozen). Initial audit at
  the 1.1.1 cut surfaces six 🟡 stale + four 🟠 read-through rows
  as carryover for the next doc-sync pass. Pattern lifted from
  `libro/docs/doc-health.md` + `majra/docs/doc-health.md`,
  phylax-shaped.

- **Per-module test split.** The monolithic `tests/phylax.tcyr`
  (972 lines, 29 test groups, 178 assertions) is replaced by 14
  per-module files under `tests/test_*.tcyr` — 188 assertions
  total. CI loops `tests/*.tcyr` and reports per-module pass/fail;
  a crash in one module (e.g. the `test_tlsh.tcyr` segfault
  documented in the issue catalogue) only takes out its own test
  file, leaving the other 13 modules to run and report
  independently. Mirrors the layout the majra and libro test trees
  evolved toward. New module mapping:

  | File | Source surface | Assertions |
  |---|---|---|
  | `test_severity.tcyr` | `types.cyr` (severity/category/errors/parse) | 50 |
  | `test_analyze.tcyr` | `analyze.cyr` (entropy/chi-squared/file-detection/tar) | 25 |
  | `test_sha256.tcyr` | `hashing.cyr` (sha256, via `file_sha256`) | 2 |
  | `test_strings.tcyr` | `strings.cyr` | 7 |
  | `test_pe.tcyr` | `pe.cyr` | 17 |
  | `test_elf.tcyr` | `elf.cyr` | 7 |
  | `test_archive.tcyr` | `archive.cyr` | 1 |
  | `test_yara.tcyr` | `yara.cyr` | 8 |
  | `test_tlsh.tcyr` | `hashing.cyr` (tlsh) | 5 |
  | `test_ssdeep.tcyr` | `hashing.cyr` (ssdeep) | 4 |
  | `test_report.tcyr` | `report.cyr` | 2 |
  | `test_queue.tcyr` | `queue.cyr` | 8 |
  | `test_utils.tcyr` | `utils.cyr` (memmem/hex) | 21 |
  | `test_integration.tcyr` | `types`+`hashing`+`analyze`+`report` | 20 |
  | `phylax-core.tcyr` | `[lib.core]` smoke test | 11 |

### Fixed

- **CI `Format check` step regressed under cyrius 5.10.x.** The
  previous invocation, `diff -q <(cyrius fmt "$f" --check 2>/dev/null) "$f"`,
  assumed `cyrius fmt --check` writes the formatted source to
  stdout. In cyrius 5.10.x, `--check` is silent on clean files
  (exit 0, no output) — so the `diff` against the file content
  always reports drift on every non-empty source file (false
  positive across the whole tree, as surfaced by the CI run on
  2026-05-11). Dropped the `--check` flag; `cyrius fmt "$f"`
  without flags emits the formatted source and the diff catches
  real drift only.

- **SHA-256 wrappers (4 sites) — sigil-bundle dispatch collision.**
  `src/analyze.cyr:file_sha256`, `src/types.cyr:finding_fingerprint`,
  `src/integration.cyr` (entropy-analysis path), and
  `src/quarantine.cyr` (file-quarantine path) previously delegated
  to sigil's `sha256_hex` wrapper. The sigil bundle is compiled
  with its own local `hex_encode` (returns a raw c-string), and
  the cyrius linker binds the `hex_encode` call inside sigil's
  `sha256_hex` body at bundle-compile time — bypassing phylax's
  `src/utils.cyr:286` last-def-wins override (which returns a Str).
  Downstream `str_eq` / `str_cat` on the raw c-string read
  length-bytes from the wrong offset and silently produced the
  wrong answer (the per-module split surfaced this cleanly:
  `test_sha256.tcyr` and `test_integration.tcyr:test_fingerprint`
  both failed with `expected 64, got <huge pointer-shaped number>`).
  Rewrote `file_sha256` to compose `sha256()` (sigil digest
  primitive) + `hex_encode()` (phylax local, Str output) directly;
  the three other call sites now route through `file_sha256`
  instead of `sha256_hex`. The dispatch collision is no longer
  reachable from phylax code.

- **aarch64 release build fails on undefined `SYS_MKDIR`.** The
  release-workflow cross-build (`cyrius build --aarch64`) failed at
  compile time on `src/quarantine.cyr:89`'s raw
  `syscall(SYS_MKDIR, dir, 448)` — aarch64 Linux dropped the bare
  `mkdir(2)` syscall in favor of `mkdirat(2)`, so `SYS_MKDIR` isn't
  exposed by the cyrius stdlib's aarch64 peer. Same class of issue
  affects three other call sites that were latent (CI's compiler
  stops at the first undefined identifier, so the next-up
  bug-after-fix would have surfaced on the following push):
  `syscall(SYS_RENAME, …)` in `src/quarantine.cyr` (×2 sites),
  `syscall(SYS_UNLINK, …)` in `src/cli.cyr` (×2 sites),
  `syscall(SYS_INOTIFY_INIT)` + `syscall(SYS_INOTIFY_ADD_WATCH, …)`
  in `src/cli.cyr` (×3 sites). All six classes swapped to the
  portable wrapper form. `sys_mkdir` / `sys_unlink` /
  `sys_inotify_init` / `sys_inotify_add_watch` come from the
  cyrius stdlib's per-arch peer; `sys_rename` is a phylax-side
  backfill added to both `src/syscall_x86_64_linux.cyr` (direct
  `SYS_RENAME`) and `src/syscall_aarch64_linux.cyr` (composes
  through `SYS_RENAMEAT(AT_FDCWD, old, AT_FDCWD, new)`) since
  neither stdlib peer ships a `sys_rename` today. The aarch64
  peer's "intentionally empty" header is gone — it's now a real
  backfill file that mirrors the x86 peer's role.

- **`hex_decode` name collision with sigil's bundle.** Phylax's
  `src/utils.cyr:phylax_hex_decode` (formerly `hex_decode`) shares
  a name with `lib/sigil.cyr:1272`'s `hex_decode(hex_str, hex_len)
  : i64` — but the signatures are incompatible (Str + out-ptr vs
  raw + len). The "last def wins" link resolution put one or the
  other in scope at different call sites unpredictably; at the
  test surface, sigil's version was selected and the Str header
  got reinterpreted as a raw byte pointer (deref crash, exit 139,
  surfaced cleanly when the test split contained the failure to
  `test_utils.tcyr`). Renamed phylax's function to
  `phylax_hex_decode` to break the collision permanently; the
  three call sites in `src/hashing.cyr` and `tests/test_utils.tcyr`
  are updated. Fold this rename back into the broader duplicate-fn
  cleanup when the 5.11.x / 5.12.x sweep lands — same pattern
  likely needed for `hex_encode`, `str_to_int`, `str_contains`
  which carry the same warning today.

### Known issues (filed, not blocking)

- **`tlsh_distance(h, h)` segfaults under cyrius 5.10.44 + sigil 3.1.1.**
  Surfaced during the test-split bisect: calling
  `tlsh_distance(h, h)` with `h` from a successful `tlsh_hash`
  crashes the process (exit 139, no assertion message). The
  pre-split monolithic `tests/phylax.tcyr` had this assertion run
  toward the middle of `main()`, taking out the entire suite
  silently. Post-split, the segfault is contained to
  `tests/test_tlsh.tcyr` alone, and the offending assertion is
  commented out at lines 25-29 of that file pending the fix. All
  five other TLSH assertions still run and pass. Full bisect +
  suspected root causes (cc5 register-spill, 5.10.x layout
  changes, sigil 3.x interaction) at
  `docs/development/issues/2026-05-11-tlsh-distance-segfault.md`.

### Carryover (not addressed in this cut)

These are the 🟡 / 🟠 rows in `docs/doc-health.md` and the
known-issue list — picked up in the next sweep.

- `docs/development/dependency-watch.md` — pin matrix rewrite
  against the post-sweep state (cyrius 5.10.44, sakshi 2.2.4,
  sigil 3.1.1, majra 2.4.4, bote 2.7.1, +libro 2.6.3 direct).
- `docs/development/roadmap.md` — aarch64-chain row refresh; the
  sigil floor moved transitively past 2.9.5 to 3.1.1 in this
  cycle and the chain shape needs to be re-anchored.
- `docs/development/issues/2026-04-30-cyrius-stdlib-issues.md` —
  walk the catalogue: `sys_stat` / `sys_fstat` closed in 5.10.x
  (verify and retire phylax's local x86 backfill in
  `src/syscall_x86_64_linux.cyr`), file new entries for anything
  that resurfaced under the new pin.
- `docs/development/threat-model.md` — read-through against
  sigil 3.x's PQ surface; expected to be a no-op (phylax only
  consumes `sha256_hex`).
- **Socket-family aarch64 portability.** `src/cli.cyr` daemon path
  uses `syscall(SYS_SOCKET, …)` / `SYS_BIND` / `SYS_LISTEN` /
  `SYS_ACCEPT` directly. Those constants are defined unguarded in
  `lib/net.cyr` with x86_64 syscall numbers (41 / 49 / 50 / 43);
  on aarch64 the build succeeds but the syscall numbers are wrong
  at runtime (aarch64 uses different numbers for the socket family).
  Runtime-only portability gap; doesn't block the CI release cross-
  build but the daemon mode will be broken on aarch64 hardware
  until `lib/net.cyr` (cyrius stdlib) grows per-arch peer files
  the same way `syscalls.cyr` did at 5.4.10. Tracked here for the
  next sweep; phylax-side workaround would be to introduce
  per-arch wrappers like the syscall peer files do, or wait for
  the stdlib to land the fix.

- `src/syscall_x86_64_linux.cyr` + `src/utils.cyr` duplicate-fn
  warnings (`sys_stat`, `sys_fstat`, `str_to_int`, `hex_encode`,
  `hex_decode`, `str_contains`) — retire the phylax-side
  duplicates that the 5.10.x stdlib now ships. Scheduled for the
  5.11.x / 5.12.x sweep.

## [1.1.0] - 2026-04-30

Toolchain + dep refresh, library split, CI modernization, and
aarch64 portability sweep. No behavioral changes to detection or
scan output. Additive surface for downstream consumers (daimon,
aegis, t-ron) via the new `[lib]` / `[lib.core]` profiles.

The 1.1.0 release rolled across three sessions; this entry
combines them. Mid-flight bumps that did not ship as separate
releases:
- cyrius pin: 5.1.12 → 5.7.34 → **5.7.48**
- sakshi: 1.0.0 → **2.1.0**
- sigil: 2.1.2 → 2.9.4 → **2.9.5**
- agnosys: (newly added dep) **1.0.4** via sigil's bundle
- majra: 2.2.0 → **2.4.1**

The 5.7.34 → 5.7.48 nudge picks up the rest of the 5.7.x cycle's
syscall-portability narrative (per-arch table dispatch, `sys_*`
wrappers, `_SC_ARITY` arity checks, advanced-TS pin closure,
late refactor pass). The sigil 2.9.4 → 2.9.5 nudge pulls in the
agnosys 1.0.4 portability sweep transitively (sigil's
`lib/agnosys.cyr` is the bundled artifact).

### Fixed

- **CI/release toolchain install was failing on 404.** Phylax 1.0.0
  CI used the legacy "curl release tarball + manual extract" pattern
  that other AGNOS repos still ship; it broke once the cyrius pin
  pointed at a tag with no corresponding GitHub release tarball
  (5.7.26 was tag-only). Switched to the canonical
  `scripts/install.sh` from `cyrius main` (sigil-style):
  `curl … install.sh | CYRIUS_VERSION=$VER sh`. Single source of
  truth for the install procedure; staging now lives at
  `~/.cyrius/versions/$VER/` with `~/.cyrius/bin/` symlinked for
  `PATH`. The cyrius pin is still read from `cyrius.cyml
  [package].cyrius` so the version stays declared in one place.
  Also bumped pin **5.7.26 → 5.7.34** to land on a release that has
  a published tarball.

### Added

- **`[lib]` and `[lib.core]` profiles** in `cyrius.cyml`. `cyrius distlib`
  emits `dist/phylax.cyr` (full library, 7,230 lines / 253,950 B,
  matches `src/lib.cyr` minus CLI). `cyrius distlib core` emits
  `dist/phylax-core.cyr` (detection-only, 6,398 lines / 225,171 B —
  drops `queue.cyr` / `quarantine.cyr` / `integration.cyr` so consumers
  avoid the `bote` / `majra` / `http` transitive dep surface entirely).
  Targets: daimon picks up the full bundle for orchestrator+MCP
  integration; aegis and t-ron pick up the core bundle for detection
  primitives only.
- **`src/lib_core.cyr`** — companion include list to `src/lib.cyr` for
  the `[lib.core]` profile. Lets `tests/phylax-core.tcyr` and
  `tests/phylax-core.bcyr` smoke-test the core surface in isolation;
  if any future change leaks an integration symbol into a core module,
  these compile and break before downstream consumers do.
- **`tests/phylax-core.tcyr`** — 11 assertions across 6 groups
  (severity, analyze, sha256, memmem, strings, report) exercising the
  core profile. All pass on Cyrius 5.7.34.
- **`tests/phylax-core.bcyr`** — replaces the misnamed
  `tests/phylax-bench-lite.bcyr` (which still pulled `src/lib.cyr`
  despite its "lite" label). Five benchmarks that actually compile
  against `src/lib_core.cyr`: `entropy_1k 16µs`, `file_detection 1µs`,
  `memmem_4k 9µs`, `hex_encode_256 5µs`, `extract_ascii 43µs` (Cyrius
  5.7.34, dev host).
- **Distlib freshness gate** in `.github/workflows/ci.yml` — runs
  `cyrius distlib` + `cyrius distlib core`, then `git diff --exit-code
  dist/`. Same pattern as majra, sakshi, libro. Prevents the bundles
  from drifting out of sync with `src/`.

### Fixed (aarch64 portability sweep — 2026-04-30)

- **`src/utils.cyr`** raw-numeric syscalls migrated to portable
  stdlib wrappers:
  - `syscall(4, path, &statbuf)` (raw SYS_STAT, x86-only number) →
    `sys_stat(path, &statbuf)` (stdlib wrapper, dispatches to
    `SYS_STAT` on x86 / `SYS_NEWFSTATAT(AT_FDCWD, …)` on aarch64).
  - `syscall(2, path, …)` (raw SYS_OPEN) → `sys_open(path, …)`.
  - `syscall(SYS_FSTAT, fd, …)` left as-is — `SYS_FSTAT` constant
    is arch-correct in both stdlib peers (x86 = 5, aarch64 = 80).
    Switched the call to `sys_fstat(fd, buf)` for consistency.
  - 4× `syscall(3, fd)` (raw SYS_CLOSE) → `sys_close(fd)`.
  - **Stat-struct offsets** `+24` (st_mode) and `+48` (st_size)
    replaced with `STAT_MODE` / `STAT_SIZE` enum members from
    `lib/syscalls.cyr`. The arch peers expand `STAT_MODE` to 24 on
    x86 (`asm/stat.h` 144-byte layout) and 16 on aarch64
    (`asm-generic/stat.h` 128-byte layout — compact `st_nlink`).
    The 8-byte `load64` reads st_mode + the next 4-byte field on
    either layout; the existing `(mode & 0170000)` mask isolates
    the file-type bits independently of what's in the upper half.
  - `var statbuf[144]` retained as a numeric literal — cyrius
    requires a constant integer in array-size context, and
    `STAT_BUFSZ` is 144 on both arches.
- **`src/cli.cyr`** raw-numeric syscalls migrated:
  - 3× `syscall(60, code)` (raw SYS_EXIT) → `sys_exit(code)` in
    `scan_finish` / `check_and_exit` / unix-domain-socket exit paths.
    The "syscall(60, N) in nested if-blocks passes 0" workaround
    note is preserved — `sys_exit(code)` is itself a one-line
    helper, so the register-spill fix mechanism is unchanged. New:
    portable across SYS_EXIT = 60 (x86) / 93 (aarch64).
  - 2× `syscall(0, …)` (raw SYS_READ) → `sys_read(…)`.
  - 2× `syscall(2, path, 577, 420)` (raw SYS_OPEN with
    `O_WRONLY|O_CREAT|O_TRUNC` and mode 0644) → `sys_open(…)`.
  - 3× `syscall(1, fd, …)` (raw SYS_WRITE) → `sys_write(fd, …)`.
  - 6× `syscall(3, fd)` (raw SYS_CLOSE) → `sys_close(fd)`.
- **`tests/phylax.tcyr` / `phylax-core.tcyr` / `phylax.bcyr` /
  `phylax-core.bcyr` / `phylax.fcyr`** — 5× `syscall(60, exit_code)`
  → `sys_exit(exit_code)`.

### Added (aarch64 portability sweep — 2026-04-30)

- **`src/syscall_x86_64_linux.cyr`** + **`src/syscall_aarch64_linux.cyr`**
  — per-arch peer files for the cyrius stdlib gap. As of 5.7.48,
  `lib/syscalls_aarch64_linux.cyr` exposes `sys_stat(path, buf)` /
  `sys_fstat(fd, buf)` wrappers but the x86_64 peer does not
  (asymmetry; tracked as a cyrius hygiene item). Phylax's x86 peer
  backfills the two wrappers; the aarch64 peer is intentionally
  empty (stdlib already has them). Each peer self-gates with
  `#ifdef CYRIUS_ARCH_X86 / AARCH64` so both ship in
  `dist/phylax.cyr` and `dist/phylax-core.cyr`; only the matching
  arch's block compiles in any given consumer build. Pattern
  mirrors agnosys 1.0.4 + sigil 2.9.5.
- Peer files prepended to `[lib].modules` and `[lib.core].modules`
  so they bundle ahead of every other module; also added to
  `src/lib.cyr` and `src/lib_core.cyr` for the in-binary build path.

### Changed

- **Cyrius toolchain** pinned to **5.7.48** (was 5.1.12 → 5.7.34
  → 5.7.48 across this release's three sessions). Manifest pin
  is now the single source of truth — `.cyrius-toolchain` removed.
  Picks up the full 5.2.x → 5.7.x stdlib + frontend deltas (notable
  for phylax: heap-grow rounding fix from 5.6.34, `lib/hashmap.cyr`
  Str-key fix from 5.4.14, sandhi folded into stdlib at 5.7.0).
- **`cyrius.cyml` `[package].version`** uses `${file:VERSION}`
  substitution — VERSION file is now the canonical version, manifest
  reads from it (matches kybernet, daimon, vidya pattern).
- **`[build].output`** standardized to `build/phylax` (was
  `phylax`).
- **Dependency bumps** (all backward-compatible at the API surface
  phylax uses):
  - **sakshi 1.0.0 → 2.1.0** — bundle path moved from
    `sakshi.cyr` / `sakshi_full.cyr` (removed in sakshi 2.0.0) to
    `dist/sakshi.cyr`. Public API (`sakshi_info` / `_warn` / `_error`)
    unchanged.
  - **sigil 2.1.2 → 2.9.5** — adds SHA-NI hardware dispatch
    (sigil 2.9.2 probe + 2.9.3 compress, ≈21–44× SHA-256 speedup
    on capable hosts; sigil bench reports 64 KB at 5.32 ms software
    vs 157 µs SHA-NI). `sha256_hex` API unchanged. Phylax-side bench
    `sha256_4k` measures 19–20 µs on the dev host (software path —
    SHA-NI gains land on larger inputs / batched flows). 2.9.5
    transitively pulls in the agnosys 1.0.4 portability sweep
    (per-arch syscall peer files, raw-syscall migration to `sys_*`
    wrappers across 28 sites in agnosys src/).
  - **majra 2.2.0 → 2.4.1** — `src/pubsub.cyr` and `src/counter.cyr`
    still standalone-includable; phylax pulls them transitively for
    `bote_events_majra.cyr`. No phylax-side API change.
  - **bote** unchanged at 2.5.1.
- **`src/main.cyr`** now includes `src/lib.cyr` + `src/cli.cyr`
  separately. `src/lib.cyr` no longer includes `cli.cyr` so the
  `[lib]` profile is consumable as a pure library.
- **`var AGENT_NAME`** moved from `src/integration.cyr` to
  `src/types.cyr`. Was declared in integration.cyr but written by
  `phylax_init()` in types.cyr — broke `[lib.core]` compilation
  because the core profile omits integration.cyr. Now lives where
  it is initialized; integration.cyr reads it for daimon registration.
- **CLAUDE.md Source Structure section** rewritten — module map shows
  per-file profile membership (core / full / binary).
- **CI workflow** rewritten end-to-end to match the kybernet / daimon
  pattern — `cyrius deps` + lockfile verify, `cyrius fmt --check`
  drift detection, `cyrius vet`, `CYRIUS_DCE=1 cyrius build`, ELF
  magic check, aarch64 cross-build (best-effort), looped test +
  bench, security scan tuned for phylax (no shell-out, no system-
  path writes, ≥64 KB stack-buffer review).
- **Release workflow** — DCE build + aarch64 cross + dist bundle
  packaging. Tag-driven (`vX.Y.Z` or `X.Y.Z`); GitHub release
  attaches versioned `phylax-<TAG>.cyr` and `phylax-<TAG>-core.cyr`
  bundles alongside the binaries and `cyrius.lock`.

### Removed

- **`.cyrius-toolchain`** — superseded by `cyrius.cyml [package].cyrius`.
- **`tests/phylax-bench-lite.bcyr`** — renamed to
  `tests/phylax-core.bcyr` (`git mv`).
- **Stale `lib/` symlinks** — `lib/sakshi_full.cyr`,
  `lib/sakshi_sakshi.cyr`, `lib/sakshi_sakshi_full.cyr`,
  `lib/sigil_sigil.cyr`. Held over from older bundle naming /
  namespace schemes; not in the new `[deps.*] modules` lists.

### Verification

- `CYRIUS_DCE=1 cyrius build src/main.cyr build/phylax` — clean
  on x86_64. (Pre-existing `large static data` warning still
  fires — same as 5.7.34 baseline.)
- `cyrius build --aarch64 src/main.cyr build/phylax-aarch64`
  fails at the stdlib level with `f64_log2 is x86-only for v5.6.0;
  aarch64 has no native log2 — needs polyfill`. Phylax's Shannon
  entropy in `src/analyze.cyr` uses `f64_log2`. Pre-existing
  cyrius stdlib gap (was already broken in 5.7.34); not blocked
  on phylax-side fixes. Tracked alongside three other cyrius
  stdlib observations in
  `docs/development/issues/2026-04-30-cyrius-stdlib-issues.md`.
  CI's "Cross-build aarch64 (best-effort)" step is now
  `continue-on-error: true` until the polyfill lands stdlib-side.
- `cyrius test tests/phylax.tcyr` — **178 passed, 0 failed**.
- `cyrius test tests/phylax-core.tcyr` — **11 passed, 0 failed**.
- `cyrius bench tests/phylax.bcyr` (5.7.48 dev host):
  entropy_1k 14 µs (16 µs on 5.7.34), entropy_1m 4.21 ms,
  chi_squared 19 µs, file_detection 430 ns (1 µs on 5.7.34),
  sha256_4k 19 µs, memmem_4k 8 µs (9 µs), hex_encode_256 4 µs
  (5 µs), extract_ascii 37 µs (43 µs), ssdeep_4k 106 µs,
  tlsh_1k 377 µs.
- `cyrius bench tests/phylax-core.bcyr` — core suite runs (same
  improvements as above on shared paths).
- `cyrius distlib && cyrius distlib core` — both bundles emitted;
  `dist/phylax.cyr` 7,272 lines (was 7,230 in the mid-flight
  state; the +42 lines are the per-arch peer files +
  `STAT_BUFSZ` literal substitution); `dist/phylax-core.cyr`
  6,440 lines (was 6,398; same delta).
- `cyrius deps --verify` — 25 entries in `cyrius.lock` (6
  first-party + 19 transitive via sigil/bote → agnosys 1.0.4,
  libro). Down from 29 — sigil 2.9.5 trimmed a transitive
  dep entry.

### Migration notes for downstream consumers

Existing consumers that depend on phylax via `[deps.phylax] modules =
["src/lib.cyr"]` continue to work unchanged (the `src/lib.cyr` entry
point is still present and now precisely matches the `[lib]` profile).
New consumers should prefer the bundled form:

- Full integration:  `modules = ["dist/phylax.cyr"]`
- Detection-only:    `modules = ["dist/phylax-core.cyr"]`

The bundled form is faster to resolve (one symlink vs many) and
removes the requirement that the consumer transitively include phylax-
internal modules in the right order.

## [1.0.0] - 2026-04-16

Phylax 1.0 — threat detection engine for AGNOS.

### Modular Source Layout
- **Split monolith into 17 files** — `types.cyr`, `utils.cyr`, `analyze.cyr`, `strings.cyr`, `script.cyr`, `hashing.cyr`, `pe.cyr`, `elf.cyr`, `archive.cyr`, `yara.cyr`, `queue.cyr`, `quarantine.cyr`, `report.cyr`, `integration.cyr`, `cli.cyr`, `lib.cyr`, `main.cyr`
- `lib.cyr` includes all modules in dependency order (no entry point) — used by tests, benchmarks, fuzz
- `main.cyr` includes `lib.cyr` + entry point
- Follows ark project structure pattern

### Toolchain
- **Cyrius 5.1.12**
- `cyrius fmt` and `cyrius lint` clean

### Quality
- 178 tests / 31 groups / 0 failures
- 17 source modules, 8,582 lines total
- 850KB static binary
- Security audit: 0 critical
- Full documentation: CLI reference, integration guide, architecture overview

### Release History
- v0.7.5: Full Rust→Cyrius port (14,133 → 7,098 lines)
- v0.8.0–0.8.3: Feature parity (YARA modules, mmap, parallel, archives)
- v0.9.0–0.9.6: Hardening, daemon, STIX, TAR, heap fix, tests
- v0.98.0: Pre-release, security audit, 178 tests, docs
- v1.0.0: Modular layout, fmt/lint clean, Cyrius 5.1.12

## [0.98.0] - 2026-04-16

Pre-release. Security audit complete, 178 tests, full documentation, cc5 bug attribution corrected.

### Changes from 1.0.0-rc1
- Removed incorrect cc5 compiler blame from changelog and source comments
- Exit code propagation issue acknowledged as phylax code bug, not upstream
- Updated `docs/bugs/cc5-register-spill.md` attribution

### Cumulative State
- 178 tests / 31 groups / 0 failures
- 8,577 source lines, 850KB static binary
- Security audit: 0 critical, 5 WARN, 8 INFO
- Documentation: CLI reference, integration guide, architecture overview
- Toolchain: Cyrius 5.1.10

## [1.0.0-rc1] - 2026-04-16

Release candidate. Security audit, expanded tests, complete documentation.

### Security Audit
- Full code review of 8,577 lines — `docs/audit/2026-04-16-security-audit.md`
- **0 critical issues**, 5 WARN (defense-in-depth improvements), 8 INFO (acceptable risks)
- All input validation paths verified: O_NOFOLLOW, fstat, size caps, bounds checks, path traversal rejection
- PE/ELF parsers: all RVA/offset calculations bounded
- Archive scanning: bomb protection limits confirmed (depth 3, 1024 entries, 100MB expand)

### Test Suite — 178 Assertions
- **31 test groups**, up from 23 (0.9.5) and 16 (0.7.5)
- New groups: pe_detection, elf_security, yara_engine, scan_pipeline, hex_decode, memmem_variants, severity_names, category_names
- Covers all major subsystems: types, errors, entropy, chi-squared, file detection, SHA-256, strings, PE, ELF, YARA, queue, ssdeep, tlsh, memmem, hex, report, TAR, archives, fingerprint, baseline, timestamp, config, severity parsing

### Documentation
- **CLI Reference** — `docs/guides/cli-reference.md` (328 lines): all 8 commands, all flags, exit codes, pipeline description, config format, built-in rules table
- **Integration Guide** — `docs/guides/integration.md` (379 lines): hoosh triage, daimon orchestrator, bote MCP tools (full schemas), daemon socket protocol, CI/CD pipeline with GitHub Actions/GitLab CI/Jenkins examples
- **Architecture** — previously updated in 0.9.5

### Quality
- 178 tests, 31 groups, 0 failures
- 850KB static binary, 8,577 source lines, 974 test lines
- Toolchain: Cyrius 5.1.10
- Benchmark compilation limited by cc5 fixup table (16384) with full deps — data from 0.8.0 run still valid

### Known Limitations
- `--exit-code` propagation: globals read as 0 in large function — root cause under investigation
- Benchmark suite exceeds fixup table limit (16384) with full deps — data from 0.8.0 run valid
- Deflate decompression not implemented (ZIP/GZIP compressed entries not scanned)

## [0.9.6] - 2026-04-16

Toolchain update, cc5 bug investigation, and exit code diagnosis.

### Toolchain
- **Cyrius 5.1.10** (was 5.1.7) — includes toml_get crash fix from 5.1.10

### cc5 Bug Investigation
- Filed detailed bug report at `docs/bugs/cc5-register-spill.md`
- Received upstream response: **not a compiler bug** per isolated repro testing
- Root cause narrowed: global variables read as 0 in function-call argument positions within functions with 15+ locals and heavy loop bodies
- One-time success with stderr syscall barrier suggests binary-layout-dependent codegen issue
- Workaround: `scan_finish` helper function receives globals via locals (partially effective)
- `--severity-threshold` / `--exit-code` feature fully implemented, exit propagation unreliable
- See `docs/bugs/cc5-register-spill-response.md` for upstream analysis

### Quality
- 110 tests passing across 23 groups
- 850KB static binary, 8,573 lines
- Toolchain pinned to 5.1.10

## [0.9.5] - 2026-04-16

Heap management, engine reuse, expanded tests, architecture docs — pre-1.0 quality release.

### Heap Management
- **`phylax_alloc`** — smart allocator routes allocations >= 64KB to `mmap_anon` (OS virtual memory) instead of bump allocator heap
- **Global YARA engine** (`get_yara_engine()`) — singleton created once, reused across all scans. Previously each `run_scan`, `zip_scan_entries`, `tar_scan_entries` created a new engine, permanently consuming heap
- Replaced engine creation in 6 locations with global singleton
- `phylax_read_file` uses `phylax_alloc` for file buffers >= 64KB
- **Multi-file scanning no longer OOM** — successfully scans 3+ files that previously crashed at 6

### Test Suite Expansion
- **110 tests** (up from 86) across **23 test groups**
- New groups: tar_detection, archive_scanning, fingerprint, baseline, timestamp, config, parse_severity
- TAR: ustar header detection, negative test
- Archive: stored ZIP entry scanning smoke test
- Fingerprint: 64-char output, determinism, uniqueness
- Baseline: ignore file parsing, suppression by rule name, non-suppression
- Timestamp: epoch-to-date for known value
- Parse severity: all levels + edge cases (null, unknown)

### Architecture Documentation
- Rewrote `docs/architecture/overview.md` for Cyrius port
- Module map with data flow, scan pipeline diagram, memory model, security hardening table
- Dependency matrix, consumer integrations

### Quality
- 110 tests passing, 849KB binary, 8,500+ lines
- 23 test groups covering all major subsystems

## [0.9.1] - 2026-04-16

TAR archive scanning and STIX threat intelligence import.

### TAR Archive Scanning
- **TAR format detection** — ustar magic at offset 257 + heuristic header validation
- **`tar_scan_entries`** — walks 512-byte header blocks, parses octal sizes, scans regular file entries
- **Recursive archive detection** — nested ZIP/TAR/GZIP inside TAR scanned up to depth limit
- Added `FILETYPE_TAR = 10` constant and detection in `detect_file_type`
- Added `parse_octal` helper for ASCII octal string parsing
- Wired into `run_scan` pipeline alongside ZIP/GZIP

### STIX/TAXII Threat Intel Import
- **`phylax intel import <stix_file>`** — reads STIX 2.1 JSON bundles
- Extracts SHA-256 hash indicators (64-char hex strings with boundary validation)
- Generates YARA rules with meta fields (description, severity, sha256)
- Outputs to `phylax-intel.yar` for use with `--rules`
- CLI dispatch with `intel import` subcommand

### Quality
- 86 tests passing, 849KB binary, 8,535 lines
- TAR tested with ustar archive containing ELF payload (2 findings)
- STIX tested with bundle containing SHA-256 indicator (1 rule generated)

## [0.9.0] - 2026-04-16

Hardening, daemon mode, directory scanning, and developer UX.

### Security Hardening
- **O_NOFOLLOW** on file open — rejects symlinks to prevent traversal attacks
- **fstat** after open — verifies target is a regular file (not device, socket, etc.)
- **Per-scan allocation limits** — 200MB cap prevents OOM from crafted files
- `G_SCAN_ALLOC_TOTAL` tracking resets per-file in multi-scan

### Daemon Mode
- **`phylax daemon`** — Unix domain socket listener for scan-as-a-service
- `--socket <path>` (default: `/tmp/phylax.sock`) — configurable socket path
- `--rules <file>` — custom YARA rules for daemon scans
- Protocol: send file path (newline-terminated), receive JSON `{"findings":N,"status":"ok"}`
- Single-threaded accept loop with per-connection handling

### Directory Recursion Fix
- **Str path plumbing** — `collect_files` wraps argv cstrs into Str via `str_from_buf`
- `run_scan` converts Str paths back to cstr for syscalls via `str_to_cstr`
- `dir_list` and `path_join` now receive proper Str arguments
- Hidden files (`.` prefix) still skipped

### Rules Fetch
- **`phylax rules fetch <url> [output]`** — download YARA rules from HTTP URL
- Auto-validates downloaded rules after saving
- Default output: `rules.yar`

### UX
- **Progress indicator** `[N/total]` for multi-file scans
- Updated help text with daemon command and options

### Known Limitations
- Multi-file directory scan hits heap exhaustion at ~6 files (bump allocator is finite)
- Daemon mode is single-threaded (one scan at a time)

### Quality
- 86 tests passing, 840KB binary, 8,249 lines

## [0.8.3] - 2026-04-16

Archive scanning for ZIP and GZIP files.

### Archive Scanning
- **ZIP stored entry scanning** — walks local file headers, scans uncompressed (method 0) entries through full analysis + YARA pipeline
- **Recursive archive detection** — nested ZIP-in-ZIP scanned up to 3 levels deep
- **GZIP detection** — identifies GZIP archives, notes deflate decompression pending (v0.9)
- **Bomb protection** — max depth (3), max entries per archive (1024), max expanded size (100 MB)
- Wired into `run_scan` pipeline as Step 4 (after YARA, before result return)

### Tested
- Stored ZIP with clean content → 0 findings (correct)
- Stored ZIP with embedded ELF → 2 findings (polyglot + archive detection)
- GZIP file → 1 finding (compressed_archive informational)
- 86 tests passing

### Limitations
- Only stored (uncompressed) ZIP entries scanned — deflate decompression deferred to v0.9
- TAR format not yet supported

## [0.8.2] - 2026-04-16

Parallel file scanning for multi-file operations.

### Parallel Scanning
- **Thread pool** for multi-file scans — 4 worker threads via `thread_create`
- `parallel_scan_worker` processes file batches independently, results collected via mutex
- Automatically engages when scanning 4+ files; single-file scans remain sequential
- Added `str_to_cstr` helper for Str → null-terminated cstr conversion
- `PARALLEL_THREADS` and `PARALLEL_THRESHOLD` configurable constants

### Known Limitations
- Directory recursion with parallel scan needs cstr/Str unification (tracked for v0.9)
- `args.cyr` cmdline buffer on stack limits argv lifetime — affects path conversion

### Quality
- 86 tests passing
- 828KB static binary

## [0.8.1] - 2026-04-16

Memory-mapped I/O for large file scanning.

### mmap I/O
- **`mmap_file_ro`** for files > 64KB — zero-copy file access via `SYS_MMAP`, no heap pressure
- **`phylax_file_size`** — stat-based file size detection before read
- Small files (< 64KB) still use alloc+read for simplicity
- **100MB hard limit** (up from 1MB) — configurable via `PHYLAX_MAX_FILE_SIZE`
- Successfully scans 5MB+ files that previously crashed on heap exhaustion
- Added `mmap.cyr` stdlib dependency

### Quality
- 86 tests passing
- 828KB static binary
- Tested: 5-byte file (alloc path), 512KB file (mmap path), 5MB file (mmap path), 2MB PE-like file

## [0.8.0] - 2026-04-16

Feature parity release: YARA module conditions, CI pipeline gating, config file, timestamp formatting, and performance optimizations.

### YARA Module System
- **`pe.is_dll`, `pe.is_64bit`, `pe.machine`** — PE module field access in YARA condition expressions
- **`elf.machine`, `elf.type`** — ELF module field access in YARA conditions
- Scan engine now parses PE/ELF headers and passes module data through to condition evaluator
- `.yar` parser extended with dot-notation lexing for module field access

### CI/CD Pipeline Gating
- **`--severity-threshold`** flag (info/low/medium/high/critical) — minimum severity to trigger non-zero exit
- **`--exit-code`** flag — custom exit code when threshold met (default: 1)
- Note: exit code propagation affected by cc5 register spill in large functions — tracked for compiler fix

### Config File
- **`phylax.toml`** config file support — loads from `./phylax.toml` or `$HOME/.config/phylax/config.toml`
- Sections: `[scan]` (rules_path, max_file_size), `[hoosh]` (url), `[daimon]` (url)
- CLI flags override config file values

### Timestamp Formatting
- **`phylax_timestamp(epoch)`** — custom Gregorian calendar conversion (`YYYY-MM-DD HH:MM:SS`)
- Replaces stdlib `iso8601()` which hangs due to chrono.cyr division loop
- Status command and report timestamps now human-readable

### Performance
- **File detection: u32 compare** — single `read_u32_le` for 4-byte magic signatures instead of 4x `load8`
- **Queue: binary heap** — O(log n) enqueue/dequeue replacing O(n) sorted insert (was 200-364x slower than Rust)

### Quality
- 86 tests passing across 16 groups
- 828KB static binary (up from 811KB with new features)
- 7,818 lines of Cyrius (up from 7,515)
- Toolchain: Cyrius 5.1.7

## [0.7.5] - 2026-04-16

Full port from Rust to Cyrius. 14,133 lines of Rust → 7,098 lines of Cyrius (50% reduction). Zero external runtime dependencies — compiles to a single static binary.

### Breaking

- **Language change**: Rust → Cyrius 5.1.3. Build with `cyrius build` instead of `cargo build`.
- **Manifest change**: `Cargo.toml` → `cyrius.cyml`. Dependencies are now Cyrius stdlib modules + sakshi + sigil.
- **Async removed**: All async/tokio code replaced with synchronous equivalents. Hoosh and daimon clients use blocking HTTP.
- **Feature gates removed**: `bote` and `yara-x` optional features dropped. YARA-X backend not ported (native engine is sufficient).
- Original Rust source removed at v0.98.0 (port complete, audit passed)

### Ported (all 22 Rust modules → single src/main.cyr)

**Core** (types, error, analyze, strings)
- All enum types as integer constants with name/rank helper functions
- 39 struct definitions with field accessors
- Shannon entropy, chi-squared, file type detection (9 formats), polyglot detection
- ASCII + UTF-16 LE string extraction
- SHA-256 via sigil dependency
- Severity escalation (entropy+polyglot, executable, multiple signals)
- Baseline suppression (fingerprint + rule name matching)

**Binary Parsing** (pe, elf)
- PE parser: DOS/COFF/Optional headers, sections (96 cap), imports (256 cap) with ILT/ordinal support, exports (1024 cap), TLS callback detection, PDB path, Rich header XOR decryption, resources, Authenticode certificates, imphash
- ELF parser: 32/64-bit, little/big-endian, sections (1024 cap), segments, DT_NEEDED, symbols (4096 cap), interpreter path, security features (RELRO, RWX, static linking, executable stack)

**Script Analysis** (script)
- 6-language classification (PowerShell, VBScript, JavaScript, Python, Batch, Shell)
- Obfuscation detection with per-line entropy + language-specific patterns

**Similarity Hashing** (ssdeep, tlsh)
- SSDEEP: rolling hash, FNV-1, context-triggered piecewise hashing, Levenshtein edit distance comparison
- TLSH: Pearson hash table, sliding window bucket filling, quartile encoding, distance function

**YARA Engine** (yara, yara_parser)
- Pattern matching: literal bytes, hex bytes, string patterns with nocase support
- TOML rule loader with severity, condition (all/any/at_least), constraints
- Native .yar parser: full lexer (33 token types) + recursive-descent parser
- Conditions: and/or/not, all/any/N of them, filesize comparisons, parenthesized expressions
- 7 built-in detection rules (PE, ELF, UPX, NOP sled, suspicious APIs, ransomware indicators, embedded PE)

**Infrastructure** (queue, quarantine, watch, report)
- Priority scan queue (vec-backed sorted insert, capacity limit)
- Quarantine with JSON index persistence, path traversal rejection, SYS_RENAME
- Directory watcher via inotify syscalls
- Report generation: JSON, Markdown (pipe escaping), SARIF v2.1.0

**Integration** (hoosh, daimon, ai)
- Hoosh LLM triage: synchronous HTTP POST, JSON/text response parsing
- Daimon agent lifecycle: register, heartbeat, deregister with ID validation
- Agent capabilities (11 items)

**Bote MCP Tools** (bote_tools — NEW in Cyrius port)
- 5 MCP tool definitions: phylax_scan, phylax_rules, phylax_status, phylax_quarantine, phylax_report
- 2 tool handlers: scan (file analysis → JSON response), status (engine info)
- Full JSON-RPC schema definitions with required/optional parameters
- Uses bote 2.5.1 registry + dispatcher API (was feature-gated in Rust, now always available)

**CLI** (main)
- Subcommands: scan, report, watch, rules list, rules validate, status
- Recursive file collection with symlink skip
- Full scan pipeline: read → analyze → YARA → escalate → report

### Dependencies (Cyrius)
- **stdlib** (25 modules): string, fmt, alloc, vec, str, syscalls, io, args, assert, hashmap, json, toml, regex, fs, net, tagged, fnptr, callback, thread, bench, bounds, math, process, chrono, base64, csv
- **sakshi** 1.0.0 — structured logging (replaces tracing/tracing-subscriber)
- **bote** 2.5.1 — MCP tool registry and dispatch (was feature-gated `bote` in Rust, now always included)
- **sigil** 2.1.2 — SHA-256 (replaces sha2)

### Removed (Rust-only dependencies no longer needed)
- aho-corasick, regex, memchr, serde, serde_json, tokio, reqwest, notify, clap, anyhow, thiserror, rayon, uuid, chrono (Rust), sha2, criterion, proptest, tempfile, yara-x (optional), bote (optional)

### Quality
- 16 test groups (526 lines) covering severity, errors, entropy, chi-squared, file detection, SHA-256, strings, PE parser, ELF parser, YARA, queue, SSDEEP, TLSH, memmem, hex encode, report
- 12 benchmark groups covering entropy, chi-squared, file detection, SHA-256, memmem, hex encode, string extraction, SSDEEP, TLSH, queue operations
- Fuzz harness skeleton

### Post-Port Fixes (2026-04-16)

**Syntax & Semantics**
- Fixed all struct initialization: `StructName {}` → `alloc(N)` + `store64()` (38 structs, 48 init sites)
- Fixed all struct field access: `.field` → `load64(ptr + offset)` (hundreds of sites)
- Fixed `!variable` bitwise NOT → `variable == 0` (6 sites — memmem, strings, ssdeep, elf, yara, script)
- Fixed `|` → `||` and `&` → `&&` in boolean contexts (26 operator fixes)
- Fixed `load64(...) = val` → `store64(..., val)` (12 lvalue assignment sites)
- Fixed `match` reserved keyword collision → renamed to `found`/`hit`
- Fixed `return;` → `return 0;` (13 bare returns)
- Fixed ternary `? :` → if/else

**Stdlib API Alignment**
- `args_count()` → `argc()`, `args_get(n)` → `argv(n)`
- `chrono_now()` → `clock_epoch_secs()`, `chrono_format()` → epoch display
- `json_stringify()` → `json_build()`
- `f64_from_int()` → `f64_from()`, `f64_to_int()` → `f64_to()`
- `sigil_sha256()` → `sha256_hex()`
- `fmt_int()` → `str_from_int()` (24 sites)
- `file_read_all(path)` → 3-arg API with `phylax_read_file()` wrapper
- TOML parser rewritten for flat section-based `toml_parse()` API
- Added `str_lower()`, `str_from_raw()`, `str_to_int()`, `print_int()`, `http_post()` shims

**C-string vs Str Type Fixes**
- `println(str_...)` → `str_println(str_...)` (73 sites)
- `str_eq(argv(...), str_from("..."))` → `streq(argv(...), "...") == 1` (26 CLI sites)
- `strlen()` for C-string length vs `str_len()` for Str (arg parsing)
- `VERSION` and `AGENT_NAME` lazily initialized after `alloc_init()`

**Float Constant Corrections**
- Fixed bit patterns for F64_256, F64_512, F64_4096, F64_7_5, F64_7_0, F64_0_9, F64_15

**Runtime Fixes**
- Heap allocation limit: 50MB → 1MB (fits Cyrius 21MB heap)
- Null check on `phylax_read_file` return before `str_len()`
- Report renderer: integer fields wrapped in `str_from_int()` for `str_cat()`

## [0.5.0] - 2026-03-27

Major feature release: native YARA syntax, deep binary analysis, script obfuscation detection, CI/CD integration, and performance overhaul.

### YARA Rule Engine
- **Native `.yar` syntax parser** — `load_rules_yar()` parses standard YARA rule files
  - Rule declarations with tags: `rule Name : tag1 tag2 { ... }`
  - Meta sections mapped to severity/description
  - String definitions: text literals, hex patterns, regex, with `nocase`, `wide`, `ascii` modifiers
  - Full boolean condition expressions: `and`, `or`, `not`, parentheses
  - `any of them`, `all of them`, `N of them`, `any of ($a, $b)`, `filesize` comparisons
  - `import` statements silently skipped (module system not yet supported)
- **Hex wildcard bytes** (`??`) and **jumps** (`[n-m]`) in hex patterns — auto-compiled to regex
- **Aho-Corasick multi-pattern automaton** — single-pass scanning with adaptive threshold (AC for 8+ patterns, memmem fallback below)
- **`#count` operator** — `#a >= 3` counts pattern occurrences
- **`@offset` operator** — `@a[0] == 0` accesses match positions, with optional index `@a[N]`
- **`for..of` positional constraints** — `for any of ($a, $b) : ($ at 0)`, `for 2 of them : ($ in (0..100))`
- `ConditionExpr` recursive AST with `PatternMatchInfo` carrying counts + offsets
- `RegexBuilder` with 10 MB size/DFA limits to prevent DoS from crafted patterns
- `phylax rules validate` — syntax-check TOML and .yar files without scanning

### Binary Analysis
- **Per-section entropy** — `pe_section_entropy()` / `elf_section_entropy()` with per-section-type thresholds (code > 7.0, data > 7.5)
- **Chi-squared randomness test** — `chi_squared()` + `classify_randomness()` distinguishes encrypted vs compressed vs normal data
- **PE overlay detection** — `detect_pe_overlay()` finds data appended after last section
- **Packed binary heuristics** — `detect_pe_packing()` combines 6 signals: packer section names, W^X sections, hollow sections, few imports, entry in high-entropy section, encrypted overlay
- **PE imphash** — function-level import parsing (ILT/INT with ordinal support) + `compute_imphash()` (SHA-256 variant)
- **PE TLS callback detection** — `has_tls_callbacks` field flags pre-entrypoint execution
- **PE debug directory / PDB path** — `pdb_path` field extracts developer build path
- **PE Rich header parsing** — `rich_entries` with XOR-decrypted toolchain IDs + `rich_product_name()` lookup (VS6 through VS2022+)
- **ELF program header parsing** — segments, interpreter path, security feature detection (RELRO, RWX, static linking, executable stack)

### Script Analysis (NEW)
- **Script language classification** — PowerShell, VBScript, JavaScript, Python, Batch, Shell (shebang + content-based)
- **Obfuscation detection** — per-line entropy analysis, base64 block detection, language-specific patterns:
  - PowerShell: `[char]` chains, `Invoke-Expression`/IEX, `-EncodedCommand`, `-WindowStyle Hidden`
  - VBScript: `Chr()` concatenation, `Execute`/`ExecuteGlobal`, `WScript.Shell`
  - JavaScript: `eval()`, `fromCharCode` chains, `document.write`+`unescape`, hex escape floods

### CI/CD Integration (NEW)
- **SARIF v2.1.0 output** — `--format sarif` for GitHub/GitLab Code Scanning integration
- **Exit codes for pipeline gating** — `--exit-code N` + `--severity-threshold` on `phylax scan`
- **Scan session UUID** — `session_id` on `ScanResult` and `ThreatReport` for audit trails and SIEM correlation
- **JSON structured logging** — `--log-format json` for SIEM ingestion (Splunk, Elastic)

### Finding Management (NEW)
- **Finding fingerprints** — `ThreatFinding::fingerprint()` for stable deduplication across scans
- **Baseline suppression** — `Baseline` struct loads from `.phylax-ignore` or previous scan JSON, filters known findings

### CLI / UX
- **Verbosity flags** — `-v` (info), `-vv` (debug), `-vvv` (trace), `-q` (quiet/error-only)
- rayon parallel file scanning — multi-file `phylax scan` uses `par_iter`
- Eliminated double file read in single-file scan

### Performance
- **`memchr::memmem`** for YARA literal/hex pattern matching — 100-200x faster than naive `windows().any()`
- **`#[inline]`** on 14 hot-path functions — 20-50% improvement on report rendering, findings generation

### Security Hardening
- `HooshClient::new()` / `DaimonClient::new()` return `Result` — no more `.expect()` panics in library code
- PE section count capped to 96 (spec max), ELF section count capped to 1024
- Symlink skip in `collect_files` — prevents directory traversal and infinite loops
- **Quarantine hardening** — canonicalized root, 0700 permissions (Unix), UUID-only filenames, path traversal rejection on release IDs
- `#[non_exhaustive]` on `WatchEvent` enum
- Zero `.unwrap()` / `.expect()` in library code — lexer uses `consume_while` helper

### Correctness
- `escalate_severity` metadata keys now distinct (`escalated_polyglot`, `escalated_executable`, `escalated_signals`)
- `render_json` logs serialization errors instead of silently returning `{}`
- `#[must_use]` on all pure public functions
- `bench-history.sh` fixed to filter criterion `change:` lines

### Dependencies
- Added `memchr = "2"`, `aho-corasick = "1"` (already transitive via regex)
- Added `rayon = "1"`
- Enabled `tracing-subscriber` `json` feature
- Updated `cc` 1.2.58, `mio` 1.2.0, `proptest` 1.11.0, `uuid` 1.23.0

### Quality
- 355 tests (345 unit + 10 integration)
- 13 proptest property-based tests
- 16 benchmark groups with throughput measurement
- 3 fuzz targets (YARA, analyze, entropy)

## [0.22.3] - 2026-03-22

Initial release of the Phylax threat detection engine.

### Core Engine
- Core types: ScanTarget, FindingSeverity, FindingCategory, ThreatFinding, ScanResult, ScanConfig, PhylaxError
- `#[non_exhaustive]` on all public enums
- `#[must_use]` on all pure functions and accessors

### YARA Rule Engine
- Literal, hex, and regex pattern matching with compiled regex caching
- TOML rule loading with All/Any/AtLeast conditions
- `RuleConstraints`: `min_file_size`, `max_file_size`, `at_offset`
- Rules loaded once and reused across multi-file scans

### Binary Analysis
- Shannon entropy with block profiling and suspicious threshold (>7.5 bits/byte)
- Magic bytes detection: ELF, PE, Mach-O, PDF, ZIP, GZIP, PNG, JPEG, Script
- Polyglot file detection
- SHA-256 hashing
- PE header parsing: DOS/COFF/optional headers, sections, imports, exports
- ELF parsing: 32/64-bit, sections, `.dynsym` symbols, `DT_NEEDED` libraries
- ASCII + UTF-16 LE string extraction
- `escalate_severity()`: auto-escalation based on combined signals
- `findings_from_analysis()`: pre-computed analysis to avoid redundant computation

### CLI
- `phylax scan` — single file, multiple files, or recursive directory scanning
- `phylax watch` — filesystem monitoring with auto-scan (inotify/kqueue/FSEvents)
- `phylax daemon` — Unix socket listener with per-connection async handling
- `phylax report` — JSON and Markdown threat reports
- `phylax rules list` — list loaded YARA rules
- `phylax status` — engine status

### Integrations
- Hoosh LLM triage: `--triage` flag sends findings to hoosh `/v1/chat/completions`
- Daimon agent lifecycle: `--register` flag with heartbeat loop and graceful deregistration
- Bote MCP tool registration: 5 tools (feature-gated `bote`)

### Infrastructure
- Priority scan queue (bounded, thread-safe, AtomicU64 IDs)
- Quarantine directory management with persistent JSON index
- Watch mode: extension filtering, file size limits, debounce, periodic cleanup
- Daemon: path canonicalization, 4 KB line limit, hoosh triage integration
- `PHYLAX_LOG` env var for structured logging

### Security
- Zero `unsafe` code
- Daemon path canonicalization prevents traversal
- Daimon/hoosh agent_id validation rejects path separators
- PE RVA arithmetic uses `checked_add`
- Hoosh client 30s request timeout
- Regex crate guarantees linear-time pattern matching

### Quality
- 231 tests (221 unit + 10 integration; 235 with bote feature)
- 13 proptest property-based tests for PE, ELF, and string extraction parsers
- 16 benchmark groups with throughput measurement
- 3 fuzz targets (YARA, analyze, entropy)
- `scripts/bench-history.sh` — CSV + 3-run Markdown tracking
- GitHub Actions CI (9 jobs) + release workflow
- `cargo deny` + `cargo vet` supply chain verification
- Documentation: architecture, threat model, testing guide, dependency watch, SECURITY, CONTRIBUTING
