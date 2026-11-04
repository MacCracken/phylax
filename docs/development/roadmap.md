# Roadmap

## Completed

### v0.7.5 — Cyrius Port (2026-04-16)
- Full port from Rust (14,133 lines) to Cyrius
- 86 tests, 804KB binary, all 22 modules ported

### v0.8.0 — Feature Parity (2026-04-16)
- YARA module conditions (pe.*/elf.*)
- Config file (phylax.toml)
- CI pipeline gating (--severity-threshold, --exit-code)
- Timestamp formatting, queue binary heap, file detection u32

### v0.8.1 — mmap I/O (2026-04-16)
- Memory-mapped file access, 100MB limit (was 1MB)

### v0.8.2 — Parallel Scanning (2026-04-16)
- 4-thread worker pool for multi-file scans

### v0.8.3 — Archive Scanning (2026-04-16)
- ZIP stored entry scanning with recursive detection
- GZIP detection (deflate decompression pending)
- Bomb protection (depth 3, 1024 entries, 100MB expand)

### v0.9.0 — Hardening & Daemon (2026-04-16)
- O_NOFOLLOW + fstat scan hardening
- Per-scan allocation limits (200MB)
- Unix domain socket daemon mode
- Directory recursion fix (Str path plumbing)
- Rules fetch from URL
- Progress indicator for multi-file scans

### v1.2.6 — P(-1) Closeout (2026-08-23)
- Hostile-input sweep of every public entry point: 17 of 29 probed calls
  segfaulted on a null buffer/handle; all now return their empty-case sentinel
- **OOB read in the ELF parser** (`read_strtab_entry`) — upper-bound-only check
  let a negative, file-derived offset read below the buffer. Found as a real
  SIGSEGV with a `PROT_NONE` guard page, not inferred
- Shared `in_bounds(off, need, data_len)` now backs ~20 offset tests in
  `pe.cyr`/`elf.cyr`; rejects negatives and cannot overflow
- `hex_encode`/`str_to_int`/`str_contains` → `phylax_`-prefixed; closes a
  return-type mismatch with sigil's `hex_encode` (Str vs cstr) reachable inside
  sigil's own `sha256_hex`. Phylax-side duplicate-fn warnings 6 → 0
- tlsh_distance segfault issue closed — does not reproduce on cyrius 6.5.35
- Suite 188 → **404 assertions across 18 files**; 0 over-reads across 6,306
  guard-page combinations; ADR 0002 records the contract

## Backlog

### v0.9.1 — TAR Support
- TAR header parsing (512-byte blocks)
- Scan embedded files in TAR archives

### v0.9.2 — Threat Intel
- STIX/TAXII JSON indicator import
- Convert indicators to YARA rules
- MalwareBazaar SHA-256 hash feed

### v0.9.3 — Deflate Decompression
- GZIP/ZIP deflate decompression for compressed entry scanning
- Inflate algorithm implementation in Cyrius

### ~~Dep hygiene — drop transitive agnosys~~ (RESOLVED)
- Closed by the ordinary pin sweeps: sigil 3.8.1 internalized its trust/firmware
  modules and dropped `[deps.agnosys]`, and phylax has been well past that tag
  for several releases (3.12.9 as of 1.2.5). No transitive agnosys edge remains.

### ~~Fix the JSON and SARIF report renderers (SIGSEGV)~~ (RESOLVED)
- Fixed on main immediately after the 1.2.5 sweep — see the CHANGELOG
  `[Unreleased]` stanza and `docs/adr/0001-string-and-json-representation-boundaries.md`.
- Root cause was two representation mistakes, not one: raw argv C-strings handed
  to functions expecting `Str` fat pointers, and a HashMap handed to `json_build`,
  which wants a flat `Vec` of `{key, value}` pairs. Both classes were also live in
  `quarantine.cyr` and `integration.cyr`.
- The pass found **three more crashes** than the original filing: markdown itself
  segfaulted once a scan produced a finding (the empty-report case was the only
  one the old test covered), `Session`/`Generated` rendered as pointer values, and
  `phylax <unknown-command>` crashed on certain argument lengths.
- Renderers now build a `json_v_*` tagged-value tree, so nesting, numbers and
  booleans are real and strings are escaped at build time. Verified: output parses
  as JSON, and the SARIF is valid 2.1.0 with a boolean `executionSuccessful`.
- Coverage: suite **188 → 342 assertions across 15 → 17 files**; JSON/SARIF output
  is parsed back rather than length-checked.

### Dep pruning — the vestigial majra/libro blocks, and the sigil double-stage
- `[deps.majra]` and `[deps.libro]` are referenced by nothing in phylax's link
  closure (staged, DCE-pruned) and have been flagged for a dedicated pruning
  pass since 1.2.4.
- ⚠ Measured at 1.2.5: **simply deleting the two blocks does not help.** The
  pull survives transitively through bote 3.3.7, phylax loses control of the
  versions, and a *larger* majra bundle is staged (locked files 65 → 79).
- The real cost is upstream: libro 2.8.12 declares sigil as a **git** dep, so
  granular `lib/sigil_*.cyr` leaves stage alongside the folded `lib/sigil.cyr`
  monolith. Both are 3.12.9, so the duplicate `sha256_hex` / `sha512_hex` /
  `hex_decode_into` definitions are inert, but they cost ~350 KB of DCE binary
  (2,207,520 → 2,562,016 B). File upstream against libro: now that sigil is a
  folded stdlib module, its git dep should follow sakshi's and be dropped.

## v1.0 Criteria

- All v0.9.x items complete
- Heap management: mmap_anon for large allocs (eliminates heap exhaustion)
- cc5 register spill fix for exit code propagation
- 95%+ test coverage
- Benchmark parity within 5x for core operations
- Security audit complete
- Stable CLI interface (no breaking changes after 1.0)
- Documentation: architecture, API reference, integration guide

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
- WASM plugin system (reconsider post-v1)

## Moving the cyrius pin to 6.6.6

**Current pin: `cyrius = "6.6.2"` (cyrius.cyml:8).** Nothing blocks the bump,
but phylax has the most 6.6.6-adjacent findings of any repo in this sibling
slice, and two of them are real bugs worth fixing in the same patch.

### Windows: phylax CAN build for PE, and it rewrites report files with `O_TRUNC`

`src/cli.cyr:741` and `src/cli.cyr:850` both do
`sys_open(path, 577, 420)  # O_WRONLY|O_CREAT|O_TRUNC, 0644` to write a report.
Before 6.6.6 a PE build's `O_TRUNC` was **not decoded** — the open succeeded and
the old tail of the previous, longer report stayed behind after the new content.
That matters here because phylax is not Linux-pinned the way it looks:
`src/syscall_x86_64_linux.cyr` is empty by design and its aarch64 peer only
backfills `rename`, so `sys_open` resolves to the vendored stdlib, and that
stdlib ships the Windows arms (`lib/syscalls_windows.cyr`, `lib/fs_win.cyr`,
`lib/process_win.cyr`, `lib/thread_win.cyr`, `lib/alloc_windows.cyr`,
`lib/sync_windows.cyr`, `lib/args_win.cyr`). Only the inotify watch path is
Linux-only. **The fix is in the compiler (`_pe_open_flags`,
`src/backend/x86/emit.cyr`), so the pin bump is the whole fix** — no source
change. Also gained on PE: opens honour the access mode, and
`file_exists`/`file_read_all` no longer ask for write access, so they now
succeed on read-only files and volumes — directly useful for a scanner.

### ⚠ `WATCH_MASK` is declared twice with DIFFERENT values, and the dist ships the wrong one

- `src/types.cyr:35` — `var WATCH_MASK = 266;` (`IN_CREATE|IN_CLOSE_WRITE|IN_MODIFY`)
- `src/cli.cyr:425` — `var WATCH_MASK = 0x0000018A;` = **394** (the same three
  plus `IN_MOVED_TO`)

6.6.6 makes "a global redeclared later wins everywhere from program start" true
(the warning was previously false — verified with a probe: a top-level read
before the second declaration returned **0** under 6.6.2/6.6.5 and returns the
last value under 6.6.6). **For the binary, nothing changes**: both readers
(`src/cli.cyr:476`, `:497`) sit *after* the second declaration, so they saw 394
before and see 394 now, and `cyrius build` under 6.6.6 exits 0.

**The live defect is the bundle.** `cli.cyr` is not in `[lib]` — `types.cyr` is.
So `dist/phylax.cyr` hands daimon / aegis / t-ron `WATCH_MASK = 266`, without
`IN_MOVED_TO`, while the CLI watches with 394. Collapse the two to one
definition in `types.cyr` and delete the `cli.cyr` copy. (`IN_CREATE`,
`IN_MODIFY` and `IN_CLOSE_WRITE` are duplicated too — `src/types.cyr:32-34` vs
`src/cli.cyr:421-423` — but same-valued, so they are only noise.) None of the
four differ in **type or size**, so none trips 6.6.6's new
`global 'X' redeclared with a different type or size` compile error — confirmed
by probe and by a clean build.

### ⚠ A pair-return already drops its tag — the exact family 6.6.6 hardened

```
warning:src/types.cyr:297:21: `scan_result_highest_severity` returns a `: stack`
  pair on another path but a SINGLE value here — the tag is dropped, so the
  caller reads this error as its TAG. Did you mean `return Err(x);`?
```

This is **pre-existing** (present under 6.6.2 and 6.6.6 alike) and is still a
*warning*, not one of 6.6.6's new hard errors — `cyrius build` exits 0 on both.
But it is a real latent bug: the caller reads the error value as the tag.
6.6.6's direction of travel is to make this class fatal; fix it now while it is
still cheap (`return None();` at the `len == 0` path is the one that mismatches).

### Everything else on the list is absent

39 structs, **all** used as heap layouts (`alloc(...)` + generated accessors) —
zero `: <StructName>` parameter/variable annotations, zero `StructName { … }`
initializers, zero struct-to-struct copies, so the new struct-copy error and the
by-value deep-copy change have nothing to act on. No `async` fns, no `operator`
fns, no top-level `{ }` blocks, no `: cstring` parameters, no locally defined
`vec_*` (with `assert` and `vec` both in `[deps] stdlib`, so assert.cyr's new
transitive `include "lib/vec.cyr"` cannot collide). `lib/regression.cyr` is not
vendored and no `regression_*` helper is called, so the new exec deadline is
irrelevant. All of `src/`, `programs/` and `tests/` pass `cyrius fmt --check`
under 6.6.6.

**Measured:** `cyrius build` under 6.6.2 and under 6.6.6 both exit 0 with the
**identical 236-line diagnostic set** (the bulk of which is the
`lib/sigil*.cyr` duplicate-fn family, not phylax's).

### Verify after bumping

`cyrius deps` (re-vendor for 6.6.6's rewritten `lib/io.cyr`), then
`cyrius build` + `cyrius test` + `cyrius lint` + `cyrius vet` +
`cyrius fmt --check` + `cyrius distlib`, and confirm the diagnostic count is
still 236 — a rise means something new fired. If the `WATCH_MASK` collapse
lands in the same patch, re-cut `dist/phylax.cyr` and tell the three consumers.

## Adopting cmdit (CLI parsing)

**Demand-gated, not a forced sweep.** phylax is a Tier-2 verb tool in the
2026-06-25 ecosystem CLI review, and one of the five it found hand-validating
enum flags. The "Stable CLI interface" v1.0 criterion applies, so each visible
delta below needs a CHANGELOG decision. Checked against the tree, not assumed.

### What is hand-rolled, and where

All of it is `src/cli.cyr`, which sits outside both `[lib]` and `[lib.core]`
(`cyrius.cyml:22-60`). No stdlib `flags`.

- **Dispatch** — `streq(argv(1), …)` in `main()` (`:1171-1363`): `help`, `scan`,
  `report`, `watch`, `rules {list|validate|fetch}`, `intel {import}`, `daemon`,
  `status`; `--help`/`-h`/`--version`/`-V` only at `argv(1)` (`:1192-1213`). No
  args → usage, exit **0** (`:1184-1187`); unknown verb or sub-verb → stdout,
  exit **1** (`:1324`, `:1342`, `:1360`). The sub-verbs read raw `argv(3)`/`argv(4)`
  (`:1297-1340`), so `rules list --x` reads a rules file named `--x`.
- **Flags are not verb-scoped.** `arg_find_option`/`arg_has_flag` (`:906-925`)
  search all of argv, first match wins, and a dangling value flag reads as absent.
  `arg_collect_positional` (`:928-961`) drops every `-` token and hard-codes the
  eight value flags to skip their values (`:944-951`) — a ninth not added there
  leaks its value into the path list. Unknown and cross-verb flags pass silently.
- **Enums with no error path** — `--format` → markdown on anything but
  `json`/`sarif` (`:402`); `--severity-threshold` → `parse_severity`
  (`src/yara.cyr:864-872`), case-insensitive, unknown → `info`; `--exit-code`
  maps 0 and non-numeric to 1 (`:1233-1238`).
- **Help drift** — `print_usage` (`:1046-1098`) omits `--severity-threshold` and
  `--exit-code` (documented at `docs/guides/cli-reference.md:29-30`) and
  `rules fetch` (which `:1293` lists), and advertises `--block-size`, which
  `cmd_scan` takes (`:279`) and never reads. `load_config` (`:1112-1165`) fills
  `CFG_*` that nothing reads — a dead cascade, so cmdit lacking one blocks nothing.

### Site → cmdit

- `argv(1)` chain → `cmdit_new("phylax")` + eight `cmdit_verb` + `cmdit_dispatch`;
  `rules`/`intel` re-enter with their own verbs on `cmdit_verb_argv(h)` (depth 2).
- One child handle per flag-taking verb (scan/report/watch/daemon) via
  `cmdit_parse_verb`, each registering only its own flags; the two scanners and
  the skip-list go away.
- `--format` → `cmdit_enum(…, "markdown", "json|markdown|sarif", …)`;
  `--exit-code` → `cmdit_int` (keep 0→1 caller-side, or `cmdit_range` 1..255 as a
  contract change); `--extensions` stays `cmdit_str` + `str_split`.
- Positionals → `cmdit_require_positionals` (scan/watch/validate), `_exact`
  (`intel import`; `report`, which silently uses only its first path, `:1265`),
  `_max` (`rules list` 1, `rules fetch` 2). They come back as raw cstrs, like
  `argv(i)`, so ADR 0001's cstr/Str boundary does not move.

### Gaps (none block)

- [ ] **Case-insensitive enum.** `cmdit_enum` matches bytes, so
  `--severity-threshold HIGH` (accepted today) would fail. Keep `cmdit_str` +
  `parse_severity`, or go lower-case-only and CHANGELOG it. One-consumer evidence
  (`src/yara.cyr:866`, the `str_lower`) for an append-only case-folding modifier.
- [ ] **Streams and exit codes.** Help and errors go to stdout and usage errors exit
  1; cmdit renders to stderr and uses 2. Keep `print_usage` (fix the three
  omissions by hand) and the existing messages; decide 1 vs 2 for the new errors
  (usage and default findings already share 1, `cli-reference.md:50-56`).
- [ ] **Offending token.** `Unknown command: X` and both sub-verb messages need X,
  which cmdit keeps internal; rebuild it from the raw argv or take its wording.
- [ ] **CHANGELOG** — unknown, cross-verb and dangling value flags now error;
  `--rules a --rules b` is last-wins; `scan p --help` shows help instead of
  scanning; `--key=value` (ignored today) works.

### The manifest change

Append after `[deps.libro]`, with `path` like the majra/bote/libro blocks.
`"io"`/`"args"` are already listed (`cyrius.cyml:64`), there is no `"flags"`, and
no pin bump is needed (the dist compiles on 6.6.2):

```
[deps.cmdit]
git = "https://github.com/MacCracken/cmdit.git"
path = "../cmdit"
tag = "1.3.0"
modules = ["dist/cmdit.cyr"]
```

- [ ] Re-cut both profiles: neither dist may reference `cmdit_`, and the `.deps`
  sidecars stay unchanged. Git deps stage transitively (the `[deps.libro]` note),
  so check daimon/aegis/t-ron's lockfiles for a DCE-pruned `dist/cmdit.cyr`.

### Tests and the output-identity bar

- [ ] No argv-level test: `tests/test_cli.tcyr` includes `src/cli.cyr` but tests
  the layer below the parser — keep it green, and add a synthetic-argv group
  through `cmdit_dispatch_argv`. `tests/phylax.fcyr` fuzzes parsers, not argv.
- [ ] No golden, and CI only builds (`ci.yml:101-105`). Capture `(stdout, stderr,
  exit)` from the current binary for every verb, sub-verb and flag, the help and
  version forms, no args and unknown (sub-)verbs; diff clean but for the
  CHANGELOG'd deltas.

Pointers: cmdit's `README.md` and `docs/adr/0002-verb-dispatch.md`; stiva's
`src/main.cyr` is the worked verb-tool migration.
