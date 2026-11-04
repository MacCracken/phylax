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

### v1.2.8 — cyrius 6.6.20 + three pre-existing defects (2026-11-03)
- cyrius 6.6.2 → **6.6.20**; majra 2.9.3 / bote 3.3.17 / libro 2.10.8 (newest tags
  pinned to 6.6.20); folded sakshi 2.5.7 / sigil 3.13.10 / bayan 1.5.12
- **Files > 64 KiB were never read** (C-style octal in the `S_ISREG` test is decimal
  in Cyrius) — scan, quarantine, rules/STIX/config loaders, MCP scan tool. Since 0.9
- **`http_post` never connected** (host C string passed as a packed IPv4) — fixed via
  6.6.9's `net_resolve_ipv4`; tested against a forked real listener
- `WATCH_MASK` collapsed to one definition (the dist had shipped 266, the CLI used 394)
- `path =` overrides removed — local builds had been vendoring sibling working trees
- Sidecars compile-verified (34 → 5 / 22 → 4); `lib/math.cyr` include seeds aarch64
- Suite 404 → **421 across 18 files**, also 421/421 on aarch64 under qemu
- Binary 915,728 → 866,640 B; 232 duplicate-fn warnings → 0

### v1.3.0 — cyrius 6.7.9 + aarch64 correctness (2026-11-04)
- cyrius 6.6.20 → **6.7.9**; majra 2.12.0 / bote 3.4.10 / libro 2.11.0 (newest
  tags pinned to 6.7.9); folded sakshi 2.5.8 / sigil 3.13.11 / bayan 1.5.13
- **aarch64 correct, not just compiling:** phylax's x86 `SYS_*` / `O_NOFOLLOW`
  globals overrode the stdlib's per-target values program-wide → `phylax watch`
  got `-ENOSYS`, the mmap path followed symlinks. 19 names removed; daemon on
  stdlib `sys_*` wrappers; x86 peer guard back to `CYRIUS_ARCH_X86`
- `tests/test_platform.tcyr` (14, live per-target checks); suite **441 / 19 files
  on x86_64 and aarch64**; CI runs the suite under qemu; releases ship aarch64
- CI/release check the lock with `cyrius deps --locked` before anything writes it
- `F64_255` / `F64_ONE` removed (mabda `const` collision for consumers)
- ⚠ DCE binary 866 KB → 2.36 MB: compaction cap (fixed in cyrius 6.7.14)

### v1.3.1 — cyrius 6.7.18 + deps latest; bayan key-type fixes (2026-11-04)
- cyrius 6.7.9 → **6.7.18**; majra 2.13.0 / bote 3.8.6 / libro 2.11.3 (latest);
  folded sakshi 2.5.10 / sigil 3.13.15 / bayan 1.11.1
- **The MCP surface never worked:** bote refused all five tools (Str names, a
  JSON string where a ToolSchema object belongs) and `phylax_scan` SIGSEGV'd on
  bote's raw-JSON arguments — fixed; tested end to end through bote's dispatcher
- **TOML YARA rules loaded no fields; the config file was never read** —
  Str keys passed to bayan's cstr-keyed `toml_get` (exposed by bayan 1.11.1's
  typed keys) — fixed with `_by_cstr` lookups
- Binary 2.36 MB → **914 KB** (6.7.14 removed the DCE compaction cap); build
  warnings 3 → 1; sidecars now name sigil/bayan/tagged themselves
- `sakshi` seeded into the sidecars (it reached consumers only via vestigial libro)
- Suite 441 → **479 / 19 files, on x86_64 and aarch64**

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

### Dep pruning — the vestigial majra/libro blocks
- `[deps.majra]` and `[deps.libro]` are referenced by nothing in phylax's link
  closure (staged, DCE-pruned) and have been flagged for a dedicated pruning
  pass since 1.2.4.
- ⚠ Measured at 1.2.5: **simply deleting the two blocks does not help.** The
  pull survives transitively through bote, phylax loses control of the
  versions, and a *larger* majra bundle is staged (locked files 65 → 79).
  Re-measure before acting; that figure predates 6.6.20.
- ~~The sigil double-stage~~ — **RESOLVED by cyrius 6.6.11** (S2): a git dep's
  thin sigil files are no longer vendored when `sigil` is a stdlib leaf. At 1.2.8
  the `lib/sigil_*.cyr` leaves are gone and the 232 duplicate-fn warnings with them.

### ~~aarch64 correctness~~ (DONE at 1.3.0)
- x86-hardcoded `SYS_*` / `O_*` / `IN_*` globals removed from `src/types.cyr`;
  daemon moved to stdlib wrappers; duplicate aarch64 `sys_rename` removed; CI's
  aarch64 step fixed (`cycc_aarch64`) and now runs the suite under qemu.
  `tests/test_platform.tcyr` keeps it honest. See CHANGELOG 1.3.0.

### ~~Binary size — the DCE compaction cap~~ (x86 RESOLVED at 1.3.1)
- cyrius 6.7.14 removed the 4,096-run cap; at 1.3.1 on 6.7.18 the x86_64 binary
  is 914 KB again (it was 2.36 MB at 1.3.0).
- Remaining: **aarch64 does not compact at all** ("no compaction repair model
  yet"), so the aarch64 binary is 3.29 MB and grows with every dep (bote-core
  is 673 fns at 3.8.6; phylax calls 3). Toolchain-side.

### Config file has no effect — the `CFG_*` globals have no readers
- Since 1.3.1 `config_apply_toml` reads `[scan] rules_path` / `max_file_size`,
  `[hoosh] url` and `[daimon] url` correctly, but nothing in `src/cli.cyr`
  consumes `CFG_RULES_PATH` / `CFG_MAX_FILE_SIZE` / `CFG_HOOSH_URL` /
  `CFG_DAIMON_URL`. Wire them in as defaults that flags override.

### TOML rule pattern type `regex`
- The TOML loader treats every pattern type other than `hex` as a literal
  string, so a `type = "regex"` pattern is matched literally. Either map it to
  the regex matcher the `.yar` path uses, or refuse it.

### Outbound HTTP and daemon hardening
- `http_post`: use `sock_send_all` (6.6.8) instead of ignoring `sock_send`'s count;
  send `Host: host:port` (6.6.11 fixed the stdlib client's equivalent).
- Daemon: the raw `sys_write(client, …)` reply path can still raise SIGPIPE;
  6.6.16's fix (CYRIUS-2026-0025, formerly CVE-74) covers the socket send path only.

### CI gate gaps
- ~~CI ran `cyrius deps` before `--verify`, so a missing lock row could not fail
  the gate~~ — closed at 1.3.0 with `cyrius deps --locked` run first.
- Nothing builds a *consumer* of `dist/phylax*.cyr`; 1.2.8 and 1.3.0 did it by
  hand in scratch (`CYRIUS_LOCAL=1` for the `path` override since 6.7.6). A tiny
  consumer job would make the sidecar contract a gate.
- Nothing gates ADR 0002's name rule. 1.3.0 found `F64_255` / `F64_ONE` by
  scanning phylax's top-level names against the toolchain's `lib/` by hand; a
  scripted version of that scan belongs in CI.

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

## ~~Moving the cyrius pin to 6.6.6~~ (DONE — superseded by the 6.6.20 bump at 1.2.8)

All four findings of the 6.6.6 plan are closed:

- **Windows `O_TRUNC` on report writes** (`src/cli.cyr` `sys_open(path, 577, 420)`)
  — fixed in the compiler at 6.6.6; the pin bump was the whole fix.
- **`WATCH_MASK` declared twice with different values** — collapsed to one
  definition in `src/types.cyr` (394 = `0x18A`, the value the CLI always used) at
  1.2.8; regression-tested in `tests/test_cli.tcyr`. 6.6.20 is the first
  toolchain to flag it ("redefined with conflicting value").
- **`scan_result_highest_severity` pair-return warning** — not emitted on 6.6.20
  (6.6.9 removed the nullary-`None()` false positive), and the function has no
  callers in phylax.
- **"Confirm the diagnostic count is still 236"** — it is now **3**: 232 of the
  236 were libro's duplicate sigil leaves, which 6.6.11 stopped vendoring.

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
