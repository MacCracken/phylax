# Changelog

All notable changes to Phylax will be documented in this file.

## [1.2.6] - 2026-08-23

**P(-1) closeout release.** Folds the crash-fix pass that followed 1.2.5 into a
cut release, and adds a full hardening sweep of the untrusted-input surface on
top of it. The sweep probed the public entry points directly instead of reading
them, and found two classes the crash-fix pass had not reached: **17 of 29
hostile calls killed the process on a null input**, and a **file-derived offset
could go negative and read below the buffer** in the ELF parser. Both are fixed,
both are regression-tested, and the offset one was caught as a real SIGSEGV
rather than inferred — by abutting the input against a `PROT_NONE` page so any
over-read faults instead of silently reading neighbouring heap.

The test suite grows **188 → 404 assertions across 15 → 18 files**. Phylax-side
`duplicate fn` build warnings go **6 → 0**, which closes a live cross-library
type-confusion hazard: phylax's `hex_encode` returned a `Str` while sigil's
returns a cstr, and phylax's won under last-definition-wins — inside sigil's own
`sha256_hex`.

### Breaking

- **Three phylax-local helpers are now `phylax_`-prefixed** (`src/utils.cyr`),
  because each shadowed a dependency symbol under last-definition-wins:

  | Was | Now | Why it mattered |
  |---|---|---|
  | `hex_encode` | `phylax_hex_encode` | phylax returned a **`Str`**, sigil returns a **cstr** — and sigil's `sha256_hex`/`sha512_hex` call it. A consumer linking `dist/phylax.cyr` alongside sigil got ADR 0001's representation bug injected into sigil's internals. |
  | `str_to_int` | `phylax_str_to_int` | phylax **stops** at the first non-digit; the stdlib's **skips** non-digits and keeps going. `"12a3"` → `12` vs `123`. |
  | `str_contains` | `phylax_str_contains` | phylax reports an empty needle as **absent**; the stdlib reports it as **present**. |

  Consumers of `dist/phylax.cyr` that called the bare names must take the new
  ones. Note the last two differed *semantically* from the stdlib functions they
  shadowed, so a caller who was silently getting phylax's behaviour keeps it
  only by renaming. This follows the `PHYLAX_ERR_*` precedent from 1.2.4 and the
  `phylax_hex_decode` that already existed — `hex_encode` was simply never
  renamed with its sibling. Full rationale in
  `docs/adr/0002-untrusted-input-contract.md`.

### Security

- **Out-of-bounds read in the ELF parser, reachable from `parse_elf` on any
  untrusted file** (`src/elf.cyr`). `read_strtab_entry` validated only the upper
  bound (`off >= data_len`). Its two inputs are ELF header fields read as u32/u64
  into a **signed** i64, so a field larger than `i64::MAX` arrives negative,
  sails past that test, and makes `max = data_len - off` *larger than the whole
  buffer* — the parser then reads below `data` and keeps going. Caught as a
  genuine SIGSEGV by the guard-page harness on mutated ELFs whose `e_shoff`
  pointed past end-of-file (2 of 5,600 combinations).
- **~20 further upper-bound-only offset tests** across `src/pe.cyr` and
  `src/elf.cyr` now route through a shared `in_bounds(off, need, data_len)`
  (`src/utils.cyr`), which rejects negative offsets, negative lengths and
  negative buffer sizes, and uses `need > data_len - off` so the comparison
  itself cannot overflow.
- **17 null-input crashes across the public entry surface.** Every detection
  primitive, parser and archive scanner now returns its existing empty-case
  sentinel for a null buffer or handle instead of dereferencing. The most
  reachable was `tlsh_distance`, which dereferenced both arguments unguarded —
  and `tlsh_hash` returns 0 for short input, so **any consumer that hashes a
  small file and compares the result killed its own process**, no malice needed.

### Fixed

- **`tlsh_distance(h, h)` no longer segfaults, and its assertion is live again**
  (`tests/test_tlsh.tcyr`). This was filed against cyrius 5.10.44 in
  `docs/development/issues/2026-05-11-tlsh-distance-segfault.md` and the test had
  been commented out ever since. It does not reproduce on 6.5.35 — the call
  returns 0 as specified — so it was a toolchain defect that the ordinary pin
  sweeps closed. Re-enabled with differing-input and null-handle cases beside it.
- **Three redundant syscall wrappers removed** (`src/syscall_x86_64_linux.cyr`).
  `sys_stat`, `sys_fstat` and `sys_rename` are now byte-identical to the cyrius
  6.5.x stdlib's, so the local copies bought nothing and cost three duplicate-fn
  warnings per build. The file itself stays — the aarch64 peer is *not* empty
  (aarch64 Linux deprecated bare `rename(2)`, so it composes one through
  `renameat`), and keeping both peers keeps the two arches symmetrical.
- **33 lint warnings → 8.** All 18 "multiple consecutive blank lines" cleared and
  7 over-long lines wrapped. The remaining 8 are single indivisible string
  literals (bote tool JSON schemas, the SARIF schema URI, a SHA-256 test vector).

### Added

- **`tests/test_hardening.tcyr`** — 57 assertions covering `in_bounds`, every
  null entry point, negative lengths, truncated PE/ELF headers, and archive
  depth limits. This is the permanent form of what the throwaway fuzz harness
  found.
- **`docs/adr/0002-untrusted-input-contract.md`** — the contract the above
  encodes: a public entry point returns its own "nothing here" sentinel for bad
  input, never dereferences, never crashes; every file-derived offset test goes
  through `in_bounds`; phylax defines no bare name a dependency also defines.

### Performance

Neutral except one line item, which is recorded because it is real and
counter-intuitive rather than because it is large.

**`shannon_entropy` pays ~1.95 us per call for its null test** — 12.95 us →
14.9 us on the 1 KiB benchmark, A/B'd over three runs each against that single
line. That is not work; it is code layout. The function allocates a 2 KiB
frequency table that already sits at the per-function stack budget (the
compiler's "oversized array local kept in shared global" note), so one more test
in that frame changes how the frame is placed. Hoisting the guard into a thin
wrapper was tried and did **not** recover it, nor did reordering the tests or
merging them into a single `||`.

Kept regardless: the cost is fixed per call, so it vanishes on real workloads —
`entropy_1m` (1 MiB) moves +0.7%, inside noise — and a scanner that dies on a
null buffer is worse than one 15% slower on a microbenchmark.

| bench | 1.2.5 | 1.2.6 | delta |
|---|---|---|---|
| entropy_1k | 12.95 us | 15.12 us | **+16.8%** (the guard, above) |
| entropy_1m | 3.844 ms | 3.859 ms | +0.4% |
| chi_squared | 16.963 us | 17.134 us | +1.0% |
| file_detection | 25 ns | 27 ns | +2 ns |
| sha256_4k | 18.947 us | 18.882 us | −0.3% |
| memmem_4k | 7.112 us | 7.113 us | +0.0% |
| hex_encode_256 | 3.483 us | 3.549 us | +1.9% |
| extract_ascii | 34.314 us | 34.2 us | −0.3% |
| ssdeep_4k | 96.702 us | 97.392 us | +0.7% |
| tlsh_1k | 369.129 us | 371.106 us | +0.5% |
| queue_enqueue | 63.338 us | 63.705 us | +0.6% |
| queue_dequeue | 9.429 ms | 9.387 ms | −0.4% |
| report_json_100 | 704.398 us | 701.139 us | −0.5% |
| report_sarif_100 | 906.905 us | 902.870 us | −0.4% |
| report_markdown_100 | 118.882 us | 118.564 us | −0.3% |

### Verification

- 29/29 hostile-input entry-point cases return their sentinel (was 17 crashing)
- **0 over-reads across 6,306 guard-page (input × parser) combinations**, over
  1,196 mutated PE/ELF/ZIP/TAR/gzip inputs — including 466 structurally-valid
  PEs built to reach the import/export/TLS/debug/cert paths
- 0 abnormal exits scanning all 1,196 inputs end-to-end through the CLI
- 404 assertions across 18 files; fmt/vet/deny clean; `deps --verify` 65/65;
  `distlib` idempotent

---

**The crash-fix pass folded in from `[Unreleased]`** follows. It landed on main
directly after the 1.2.5 sweep and is released here for the first time.


Crash-fix pass over the report renderers and the CLI argument paths. Four
`phylax` invocations exited 139 (SIGSEGV); all four trace to two
representation mistakes — a HashMap handed to a builder that wants a flat
`Vec` of `Str` pairs, and raw argv C strings handed to functions that want
`Str` fat pointers. Both classes were also live in `quarantine.cyr` and
`integration.cyr`. The test suite grows from 188 assertions across 15 files
to **342 across 17** in this pass alone (the hardening sweep above then took it
to 404 across 18); every renderer now has its own assertions and the JSON/SARIF
output is parsed back rather than length-checked.

### Fixed

- **`phylax report --format json|sarif` segfaulted on every input**
  (`src/report.cyr`). Both renderers built their document with `map_new()` /
  `map_set()` and serialized it with `json_build()`. `json_build` takes a
  `Vec` of 16-byte `{key: Str, value: Str}` pairs; given a HashMap it reads
  the map header's `cap` field (offset 8) as a vec length and walks the
  24-byte entry array on an 8-byte stride, dereferencing empty slots as pair
  pointers. It also cannot express nesting, integers or booleans, which is
  what these documents are made of. Both renderers now build a
  `json_v_*` tagged-value tree, so `summary`, `results`, `findings`,
  `runs` and `locations` are real nested containers, counts and timestamps
  are JSON numbers, `executionSuccessful` is a JSON boolean, and strings are
  escaped at build time (a path containing `"` or `\` previously produced
  output no parser would accept).
- **`phylax report --format markdown` segfaulted as soon as a scan produced
  a finding** (`src/report.cyr`, `src/cli.cyr`). The findings table appended
  `ScanTarget.data` with `str_cat`, but `run_scan` stored the C-string form
  of the path there, so `str_cat` read the eight bytes past the path's NUL as
  a length. Only the empty-report case survived — which is exactly the case
  the old test covered. `ScanTarget.data` is now documented and used as a
  `Str` everywhere (`src/types.cyr`); `run_scan` stores the `Str` path and
  keeps a separate cstr for the syscalls.
- **Markdown report printed pointer values for `Session` and `Generated`**
  (`src/report.cyr`). Both fields are `Str`, but were rendered with
  `str_from_int`, so a report read `- **Session**: 140538351267216`.
- **`phylax rules validate <file>` segfaulted on every file**
  (`src/cli.cyr`). `arg_collect_positional` yields raw argv cstrs;
  `cmd_rules_validate` passed them straight into `str_cat` for its `[OK]` /
  `[FAIL]` / `[WARN]` lines. It also called `str_len` on
  `phylax_read_file`'s return without checking for the 0 it returns on a
  failed read.
- **`phylax <unknown-command>` segfaulted when the argument contained the
  wrong trailing bytes** (`src/cli.cyr`). `str_cat(str_from("Unknown
  command: "), cmd)` on the argv cstr; short arguments happened to find a
  small value past the NUL and merely printed an empty name, longer ones
  crashed.
- **`phylax watch` scanned the wrong path and ignored `--extensions`**
  (`src/cli.cyr`). The event loop extracted the changed filename into a
  buffer and then discarded it, scanning the watched *directory* instead,
  and the extension filter was a loop that unconditionally set
  `should_scan = 1`. The watch registration also passed argv cstrs to
  `dir_list` / `path_join` / `str_cat`, and keyed its watch-descriptor map
  with `str_from_int` values through the cstr-keyed `map_new()` (the stdlib
  documents that this silently drops entries; it is now `map_new_str()`).
  A new `path_has_extension` accepts `txt` and `.txt` alike.
- **`phylax rules list <file>` and `--rules <file>` read a cstr as a `Str`**
  (`src/cli.cyr`). `str_len` on an argv pointer yielded whatever eight bytes
  followed the NUL, so a rules file could be silently skipped depending on
  argv layout. Both now use `strlen`, and guard `phylax_read_file`'s 0.
- **`--hoosh-url` and `--extensions` mixed representations**
  (`src/cli.cyr`). `--hoosh-url` was a `Str` when defaulted and a cstr when
  supplied, then `str_len`'d; `--extensions` was `str_split`'d as a cstr.
  Both are normalized to `Str` at the argument-parsing boundary.
- **The quarantine index was never written and never loaded**
  (`src/quarantine.cyr`). Three separate faults on one path:
  `quarantine_save_index` fed `json_build` a `Vec` of HashMaps; it passed
  the `Str` header pointer to `file_write_all`, which wants a raw buffer, so
  the bytes written were the fat-pointer header rather than the JSON; and it
  passed a `Str` path to `file_open`, which wants a cstr. `quarantine_new`
  then ran `map_get` over `json_parse`'s flat pair `Vec`. The index is now a
  proper JSON array of objects built and parsed with `json_v_*`, with
  `timestamp` and `size` preserved as integers, and round-trips under test.
- **`quarantine_file` segfaulted on every call** (`src/quarantine.cyr`).
  `quarantine_gen_id` built its identifier with `str_cat(fmt_hex(ts), …)`.
  `fmt_hex` *prints* to stdout and returns 0, so the id generator wrote
  stray hex digits to stdout and then dereferenced 0 as a `Str`. It now uses
  `fmt_hex_buf`, the buffer-filling variant.
- **Every Hoosh and Daimon request body was built with the wrong builder**
  (`src/integration.cyr`). `hoosh_triage_finding`, `daimon_register`,
  `daimon_heartbeat` and `daimon_deregister` all passed a HashMap to
  `json_build` — the same SIGSEGV as the report renderers. The response side
  was equally wrong: it handed the whole HTTP response struct to
  `json_parse` instead of the body, then ran `map_get` over the flat pair
  `Vec` that `json_parse` returns. Bodies now build with `json_v_*`;
  responses parse `str_new(http_body(resp), http_body_len(resp))` with
  `json_v_parse` and read `choices[0].message.content` / `agent_id`
  through `json_v_obj_get`. The `Content-Type` argument was also being
  passed a full `Str` header line where `http_post` wants a bare cstr media
  type, and the URL was a `Str` where a cstr is required.
- **`parse_triage_response` read `confidence` as a pointer**
  (`src/integration.cyr`). `json_parse` returns `Str` values, so the
  `0..100` clamp compared a heap address; it now reads a real integer.

### Security

- **`http_post` bounded its request-header buffer** (`src/utils.cyr`). The
  4 KiB scratch buffer was filled with `memcpy` from a caller-supplied URL's
  host and path (`--hoosh-url`, config file) with no length check. The
  combined header length is now validated against the buffer before any
  copy, and an oversized request is refused with a logged error.
- **`http_post`'s error returns left the response struct half-initialized**
  (`src/utils.cyr`). The bad-URL, socket-failure and connect-failure paths
  set only `status`, leaving the body pointer and body length as whatever
  the bump allocator last had there. Callers that read the body — which the
  fixed `integration.cyr` now does — would take a wild pointer and a garbage
  length. All early returns go through a single zeroed `http_post_err()`.

### Changed

- **`ScanTarget.data` is a `Str`** (`src/types.cyr`). The field was
  produced as a cstr by `run_scan` and as a `Str` by `archive.cyr`, and
  consumed both ways. It is now documented as a `Str` (0 for
  `SCAN_TARGET_MEMORY`) and used consistently; `finding_fingerprint` and all
  three renderers read it directly. Consumers constructing a `ScanTarget`
  must pass `str_from(path)` rather than a bare literal.
- **`md_escape_pipe` does what its name says** (`src/report.cyr`). It was
  dead code that allocated a one-byte buffer per character in a loop and
  returned its input unchanged. It now escapes `|` and folds CR/LF to a
  space, and the markdown findings table actually calls it, so a rule name
  or description containing a pipe no longer breaks the table.
- **SARIF `startTimeUtc` is RFC 3339** (`src/report.cyr`). SARIF §3.30.7
  requires a `dateTime`; the field carried phylax's human
  `YYYY-MM-DD HH:MM:SS` form, which no SARIF validator accepts.

### Performance

- **Markdown rendering is no longer quadratic in finding count**
  (`src/report.cyr`). `report_render_markdown` accumulated with `str_cat`,
  which copies the entire buffer on every append; it now uses
  `str_builder`. Measured on a synthetic report (`report_markdown_100`,
  1000 iterations):

  | Findings | `str_cat` (1.2.5) | `str_builder` | Speedup |
  |----------|-------------------|---------------|---------|
  | 10       | 189.06 µs         | 15.74 µs      | 12.0×   |
  | 100      | 9.045 ms          | 119.39 µs     | 75.8×   |

  A 10× larger report cost 47.8× more time before and 7.6× more now.

- New benchmarks for all three renderers at 100 findings:
  `report_json_100` 782.86 µs, `report_sarif_100` 1.002 ms,
  `report_markdown_100` 118.11 µs. These paths had no benchmark before
  because two of the three could not run.

- No change to the detection benchmarks: `entropy_1k` 14.86 µs, `entropy_1m`
  3.95 ms, `chi_squared` 17.84 µs, `file_detection` 1.36 µs, `sha256_4k`
  19.47 µs, `memmem_4k` 8.37 µs, `hex_encode_256` 4.84 µs, `extract_ascii`
  34.37 µs, `ssdeep_4k` 98.56 µs, `tlsh_1k` 367.51 µs.

### Tests

- **`tests/test_report.tcyr`: 2 → 85 assertions.** The file claimed to cover
  "JSON / Markdown / SARIF" but only called `report_render_markdown`, on an
  empty report. Each renderer now has its own group; JSON and SARIF output is
  parsed back with `json_v_parse` and walked field by field (nesting, number
  vs string tags, severity→SARIF-level mapping, `artifactLocation.uri`,
  RFC 3339 `startTimeUtc`), plus metacharacter round-trips, markdown pipe
  escaping, and null-`ScanTarget.data` handling for all three.
- **`tests/test_cli.tcyr` (new, 27 assertions).** First test to include
  `src/cli.cyr`, so the argv-cstr boundary is covered directly:
  `cmd_rules_validate` over valid / unreadable / rule-less / mixed batches,
  `collect_files`' cstr→`Str` handoff, `run_scan` storing a `Str` target
  and surviving all three renderers with real findings, `--rules` with
  missing and blank paths, and `path_has_extension`.
- **`tests/test_quarantine.tcyr` (new, 43 assertions).** `quarantine.cyr`
  had no test at all. Covers id validation and generation, the full
  index save→reload round-trip (including that `size` and `timestamp` come
  back as integers), release-by-id with traversal and unknown-id rejection,
  and the missing-source path.
- `tests/test_integration.tcyr` updated for the `ScanTarget.data` contract
  and pins it with an assertion.

## [1.2.5] - 2026-08-23

Toolchain + dependency sweep onto cyrius **6.5.35** (a minor-line move, 6.4.66
→ 6.5.35, 58 releases) with all five first-party dep pins at their latest
released tags. The structural change is that **sakshi and sigil are no longer
git deps** — the 6.5.x toolchain snapshot vendors both, and declaring a folded
module as a git dep silently omits it from the generated consumer sidecars.
Two latent defects fell out of the sweep and are fixed here: the CI format
gate had been quietly broken by an upstream breaking change, and the version
string the binary prints (and stamps into every report) had drifted two
releases behind `VERSION`. All 188 assertions across the 15 test files pass;
build, fmt, lint, vet, deny and dist-freshness gates clean.

### Changed

- **Cyrius toolchain pin: 6.4.66 → 6.5.35.** No phylax source change required
  for the bump itself. 6.5.0's `public` / `private` file-scoped visibility is
  opt-in per file, so nothing in the tree changed behaviour on adoption.
- **Dependencies** (all at latest released tags): sakshi 2.4.6 → **2.4.11**,
  sigil 3.12.1 → **3.12.9**, majra 2.5.1 → **2.7.0**, bote 3.1.4 → **3.3.7**,
  libro 2.8.2 → **2.8.12**. majra and libro are moved to exactly the tags bote
  3.3.7 pins transitively, so the two never diverge inside one link.
- **`sakshi` and `sigil` moved from `[deps.X]` git blocks into `[deps] stdlib`.**
  The 6.5.x snapshot folds both (`lib/sakshi.cyr`, `lib/sigil.cyr`), and it
  folds precisely the versions this repo had been pinning forward by hand —
  sakshi 2.4.11 and sigil 3.12.9 — so the fold costs no version movement.
  The declaration *shape* is what mattered: `cyrius distlib` classifies a git
  dep out of the stdlib leaves, so both names were missing from
  `dist/phylax.deps` / `dist/phylax-core.deps` entirely. A consumer
  provisioning strictly from a sidecar would link with `sha256_*` / `sakshi_*`
  undefined. Diagnosed upstream in a clean room by majra 2.6.8; phylax's
  sidecars now carry both. `[deps.X]` git blocks drop 5 → 3.
- **Consumer sidecars went from 1 declared leaf to 32 (full) and 15 (core).**
  Both sidecars had been emitting only `thread_local`; cyrius 6.5.29's fix for
  empty named-profile sidecars is what makes the rest resolve. This is the
  half of the fold that consumers (daimon, aegis, t-ron) actually feel.
- **63 lines reformatted across 10 files** by 6.5.28's paren-aware formatter,
  which now tracks continuation indent inside unclosed parens (canonical is 2
  spaces per open-paren level, 4 accepted). Whitespace-only: `git diff -w` is
  empty and the DCE binary is byte-identical across the reformat.

### Fixed

- **The CI format gate was broken by cyrius 6.5.28 and would have failed the
  whole tree while silently rewriting it.** 6.5.28 made `cyrius fmt <file>`
  rewrite the file **in place**, and changed stdout from the formatted source
  to a one-line report. The step's `diff <(cyrius fmt "$f") "$f"` pattern
  therefore broke two ways at once: the bare invocation reformats the very
  checkout it is auditing, and the diff then compares a one-line report
  against every non-empty source file. Adding `--dry` fixes only the first
  half — it reports without writing, but does not restore a pipeable stream.
  The step now uses `cyrius fmt --check`, which exits non-zero and names the
  first differing `file:line` itself. (`--check` was unusable when this gate
  was written — it was silent on clean files in 5.10.x — and 6.5.28 fixed that
  too.)
- **`--version` and every report's `scanner_version` had drifted two releases
  behind.** `src/types.cyr` hardcodes the version string and does not derive it
  from `VERSION`; it still read `1.2.3` while `VERSION` said `1.2.4`, so the
  1.2.4 binary and every JSON / SARIF / Markdown report it stamped claimed to
  be 1.2.3. Corrected to 1.2.5, and the CI "Verify version consistency" job now
  compares `src/types.cyr` against `VERSION` instead of only grepping
  CHANGELOG, so the two cannot separate again.
- **A reachable undefined function (`chan_try_send`) is gone from the build.**
  It was reaching codegen as a trapping `ud2` under the old stack — a build
  that printed OK and would SIGILL if that path were ever taken. bote 3.3.7
  resolves it, and cyrius 6.5.x independently now *refuses* to emit a binary
  with reachable undefined functions, converting this whole failure class from
  a runtime SIGILL into a build error.

### Performance

**No change. The sweep is performance-neutral, and the raw numbers say
otherwise only because the harness changed underneath them.**

cyrius **6.5.19** rewrote `bench_run`: it now auto-batches (sizing chunks so
one clock pair is ≤1 % of the window) and subtracts a **measured** timer floor,
where it previously wrapped a clock pair around every single iteration. On this
box one clock read costs ~1.34 µs, so every pre-6.5.19 row carried that floor.
Subtracting exactly one floor from each old number reconciles all twelve rows
to within ±3 %:

| bench | raw before | before − floor | after | delta |
|---|---|---|---|---|
| entropy_1k | 15.841 µs | 14.502 µs | 13.682 µs | −5.7 % |
| entropy_1m | 3.913 ms | 3.912 ms | 3.836 ms | −1.9 % |
| chi_squared | 17.903 µs | 16.564 µs | 17.002 µs | +2.6 % |
| file_detection | 1.366 µs | 27 ns | 24 ns | −11.1 % |
| sha256_4k | 20.199 µs | 18.860 µs | 18.866 µs | +0.0 % |
| memmem_4k | 8.419 µs | 7.080 µs | 7.133 µs | +0.7 % |
| hex_encode_256 | 4.892 µs | 3.553 µs | 3.465 µs | −2.5 % |
| extract_ascii | 35.174 µs | 33.835 µs | 34.139 µs | +0.9 % |
| ssdeep_4k | 99.903 µs | 98.564 µs | 97.753 µs | −0.8 % |
| tlsh_1k | 370.588 µs | 369.249 µs | 367.218 µs | −0.6 % |
| queue_enqueue | 63.123 µs | 61.784 µs | 62.949 µs | +1.9 % |
| queue_dequeue | 9.245 ms | 9.244 ms | 9.296 ms | +0.6 % |

`file_detection` is the row that makes the point: 1.366 µs → 24 ns reads as a
57× win and is nothing of the kind — the old row was ~98 % timer. It was
verified not to be dead-code elimination before the floor was blamed: an
instrumented copy accumulating `detect_file_type` into a global sink measured
the same 26 ns as the discarding original (vs 13 ns for the `alloc` alone), and
the sink held the expected 300,000. **Do not compare any bench row in this
repo across the 6.5.19 boundary without subtracting one floor from the older
side.**

### Notes

- **The DCE binary grew ~16 %, 2,207,520 → 2,562,016 bytes**, and this is
  upstream dep shape rather than anything phylax does. libro 2.8.12 pulls sigil
  as a *git* dep (`src/sha256.cyr`, `src/hex.cyr`, `src/sha_ni.cyr`,
  `dist/sigil-mldsa.cyr`), which stages those granular leaves as
  `lib/sigil_*.cyr` alongside the folded `lib/sigil.cyr` monolith — both at
  3.12.9, so the duplicate `sha256_hex` / `sha512_hex` / `hex_decode_into`
  definitions are behaviourally inert, but they are carried twice. Dropping
  phylax's own `[deps.majra]` / `[deps.libro]` blocks does **not** avoid this:
  measured, it leaves the transitive pull intact via bote 3.3.7, surrenders
  version control, and stages a *larger* majra bundle (locked files 65 → 79).
  The fix belongs upstream in libro, now that sigil is folded.
- **The manifest's `stdlib` array does not skip comments, and mis-parses two
  ways.** An opening square bracket inside an in-array comment ends the array
  (the entries below it vanish, no error, green build — this silently dropped
  `sakshi` and `sigil` from the sidecars on the first attempt), and a
  double-quoted phrase inside one is collected as a module name (resolution
  then fails on a path built from prose). Both were hit while writing this
  release; `cyrius.cyml` now carries the rationale below the array rather than
  inside it, with a warning not to move it back.
- `cyrius.lock` grows 59 → 65 entries. `dist/` bundles rebuilt at v1.2.5
  (line counts unchanged at 7,394 / 6,541; byte counts move only with the
  reformat and the version string).

### Known, not fixed

- ~~**`report --format json` and `report --format sarif` segfault (exit 139), as
  does `rules validate <file>`.**~~ **FIXED — see the `[1.2.6]` section
  above**, which landed on main directly after this sweep. Recorded here as
  found because the diagnosis belongs with the release that surfaced it: it was
  **pre-existing and unrelated to this sweep** (reproduced identically on the
  1.2.4 build), and it hid because `tests/test_report.tcyr` exercised only
  `report_render_markdown` despite its header claiming JSON / Markdown / SARIF
  coverage. The fix pass found three further crashes this note had missed,
  including markdown itself once a scan produced a finding. Note the crash loses
  buffered stdout, so a redirected run yields an empty file rather than an
  obvious failure.
- `bench-latest.md` is still the 2026-03-26 Rust-era table (criterion
  benchmark names that no longer exist in this tree). Not regenerated here
  because `scripts/bench-history.sh` overwrites it from a `bench-history.csv`
  that is gitignored, which would replace the historical table with a
  single-column one.

## [1.2.4] - 2026-07-17

Toolchain + dependency sweep onto cyrius **6.4.66**, refreshing all five
first-party dep pins to their latest released tags. The bote 2.x → 3.x
major bump required a consumption-model change (hand-picked src modules →
the upstream core bundle), and the sweep surfaced a latent error-constant
collision now fixed by namespacing phylax's error codes. All 188
assertions across the 15 test files pass on the new stack; build, lint,
vet, deny, and dist-freshness gates clean.

### Breaking

- **Error codes renamed `ERR_*` → `PHYLAX_ERR_*`** (`src/types.cyr`). All
  eleven constants (`PHYLAX_ERR_NONE` … `PHYLAX_ERR_AGENT`) are namespaced,
  mirroring bote's `BOTE_ERR_*` and libro's `LIBRO_ERR_*`. Consumers that
  reference phylax's bare `ERR_*` constants from `dist/phylax.cyr` must
  rename to the `PHYLAX_ERR_*` form. See **Fixed** for the motivation.

### Changed

- **Cyrius toolchain pin: 6.3.15 → 6.4.66.** No phylax source change
  required for the bump itself — the 6.4.65 `thread_local_alloc()`
  addition and the TLOCAL_MAX_SLOTS 16→128 growth land transparently
  through the `lib/thread_local.cyr` opt-in phylax already includes.
  cyrius 6.3.32 also made `sync.cyr` the sole owner of `mutex_*`,
  eliminating the three `duplicate fn 'mutex_*'` build warnings phylax
  emitted since 1.2.2.
- **Dependencies** (all bumped to latest released tags): sakshi 2.4.3 →
  **2.4.6**, sigil 3.9.8 → **3.12.1**, majra 2.5.0 → **2.5.1**, bote
  2.7.7 → **3.1.4**, libro 2.7.9 → **2.8.2**.
- **bote consumption model: 11 hand-picked `src/*.cyr` modules →
  `dist/bote-core.cyr`.** bote 3.0.0 reorganized its layout — `dispatch.cyr`
  now pulls `prompts.cyr` + `resources.cyr` (added to bote's `[lib.core]`),
  whose `prompt_registry_*` / `resource_registry_*` / `prompt_def_name`
  symbols the old hand-picked list omitted, so a naive tag-only bump fails
  to link with 5 undefined functions. The upstream transport-free core
  bundle is self-contained on `hashmap` + `bayan` (both already declared)
  and exports the three symbols phylax consumes (`tool_def_new`,
  `registry_register`, `dispatcher_handle`) with unchanged signatures —
  `src/integration.cyr` is untouched. The 28-module `dist/bote.cyr` was
  deliberately not used (it drags in the full transport + libro/majra
  stack for three functions).
- **`[deps.majra]` and `[deps.libro]` are now vestigial.** Switching bote
  to `dist/bote-core.cyr` (which excludes `events_majra.cyr` /
  `audit_libro.cyr`) removes the last transitive references to majra and
  libro from phylax's link closure; phylax calls neither directly, so both
  now stage but DCE-prune. Kept and version-tracked (aligned to bote
  3.1.4's own transitive pins) as candidates for a dedicated dep-pruning
  pass.

### Fixed

- **Error-constant collision** surfaced by the dep refresh
  (`src/types.cyr`, `src/yara.cyr`, `tests/test_severity.tcyr`). phylax's
  bare `ERR_*` codes collided with the identically-named constants other
  bundled deps define — notably sakshi's `ERR_TIMEOUT = 5` vs phylax's
  `ERR_TIMEOUT = 3` — producing a `duplicate symbol 'ERR_TIMEOUT' …
  conflicting value (last definition wins)` link warning, i.e. link order
  could silently substitute the wrong value into phylax's `err_name`.
  Namespacing to `PHYLAX_ERR_*` (see **Breaking**) removes the collision.

### Performance

No regression on the new stack (12-benchmark suite): `sha256_4k` 19.8µs
(sigil 3.12.1's `thread_local_alloc`-based crypto-bank path — healthy, no
SIGILL), `entropy_1k` 14.8µs, `entropy_1m` 4.14ms, `chi_squared` 19.0µs,
`file_detection` 395ns, `memmem_4k` 8.4µs, `hex_encode_256` 4.15µs,
`extract_ascii` 37.1µs, `ssdeep_4k` 98.8µs, `tlsh_1k` 366µs.

## [1.2.3] - 2026-07-01

**AGNOS cross-build readiness.** phylax now compiles cleanly under
`cyrius build --agnos`. Host build byte-identical (the agnos change is
`#ifdef CYRIUS_TARGET_AGNOS`-gated); 188 assertions still pass.

### Changed
- **Dropped the unused `callback` stdlib dependency** (`cyrius.cyml`). phylax
  used none of `callback.cyr`'s helpers, but including it dragged in its
  `fork_with_pre_exec` (`sys_fork` / `sys_execve`) — undefined on agnos's frozen
  syscall surface — which blocked the `--agnos` build. Removing the unused dep
  clears it (no unnecessary dependencies). Root-cause stdlib gap filed upstream:
  `cyrius .../issues/2026-07-01-callback-fork-with-pre-exec-unguarded-agnos.md`.

### Fixed
- **`--agnos` build**: guarded `cmd_watch` (`src/cli.cyr`), the inotify-based
  directory watcher, behind `#ifndef CYRIUS_TARGET_AGNOS`. agnos has no inotify
  (`sys_inotify_init` / `sys_inotify_add_watch`), so `watch` fail-closes there
  with a clear message; the one-shot `scan` path is unaffected.

## [1.2.2] - 2026-06-30

Tier-4 (consumer) step of the coordinated base-security-stack migration
to cyrius **6.3.15** (sakshi 2.4.3 → sigil 3.9.8 → majra 2.5.0 → libro
2.7.9 → bote 2.7.7 → **phylax 1.2.2**). Toolchain pin + dependency
refresh, plus one real latent-bug fix the 6.3.x arity check surfaced. All
188 assertions across the 15 test files pass on the new stack.

### Changed

- **Cyrius toolchain pin: 6.2.20 → 6.3.15.**
- **Dependencies**: sakshi 2.4.3, sigil 3.9.8, majra 2.5.0, bote 2.7.7,
  libro 2.7.9 (the migrated tiers below phylax).
- **`[deps] stdlib`**: added `atomic` + `sync` — patra 1.12.7 (pulled
  transitively through libro's dist bundle on 6.3.x) declares
  `lib/sync.cyr` as a hard stdlib dep, and `sync` builds on `atomic`.

### Fixed

- **Quarantine index was never persisted to disk** (`src/quarantine.cyr`
  `quarantine_save_index`). The call `file_write(load64(mgr + 16),
  json_str)` was doubly wrong: `mgr + 16` holds the `index.json` *path*
  (set via `path_join` in the ctor, read back by `phylax_read_file`), not
  an fd, and the `len` argument was omitted entirely — so on 6.2.x the
  write silently no-op'd. Corrected to `file_write_all(path, json_str,
  str_len(json_str))`, which opens/writes/closes by path (matching the
  read side). 6.3.x's stricter arity check surfaced the latent bug.

## [1.2.1] - 2026-06-17

Toolchain + dep pin sweep onto the cyrius 6.2.x line, with the latest
first-party dep tags. No detection behavior changes in `src/`; the
source edits are the engine version string plus a single explicit
stdlib `include` (the `thread_local` opt-in below). The bump surfaced
two build-breaks the sweep resolves — both rooted in cyrius 6.2.x making
stdlib auto-association first-party-only — captured in **Fixed**.

### Changed

- **Cyrius toolchain pin: 6.1.27 → 6.2.20.** Stays on the 6.2.x
  frontend/codegen line. Nothing between the two slots carves stdlib
  surface phylax consumes (the bayan carve at 6.1.25 already landed in
  1.2.0); the relevant 6.2.x deltas are internal — the aarch64-Linux
  socket-syscall ESYSXLAT renumbers (6.2.10), the macOS/Windows clock
  reroute fixes (6.2.13–6.2.16), and the sigil 3.8.0 vendored refold
  (6.2.13). `lib/` remains a derived artifact, rehydrated by `cyrius
  deps` against the pinned snapshot + git bundles.

- **First-party dep pins, all bumped to latest released:**
  - **sakshi 2.2.10 → 2.3.1** — patch/minor cycle, logging surface
    unchanged at phylax's call sites.
  - **sigil 3.7.8 → 3.8.0** — phylax's only sigil surface is `sha256`.
    3.8.0's bundle is correctly inlined (the 3.7.11 distlib-inliner fix
    is in) and its `cbank` crypto-cache path still routes through
    `thread_local_*`; see **Fixed**.
  - **majra 2.4.5 → 2.4.7** — patch refresh, pubsub/counter surface
    unchanged at phylax's transitive call sites.
  - **bote 2.7.3 → 2.7.6** — bote 2.7.6 now pins libro 2.7.4 itself,
    so the phylax-side libro override is aligned to that (below).
  - **libro 2.7.2 → 2.7.4** — kept as an explicit pin matching bote's
    transitive pin so the resolved version is explicit and doesn't drift
    silently with bote's transitive pin.

### Fixed

- **`sha256` SIGILL (exit 132) under cyrius 6.2.x — `thread_local` opt-in
  is now explicit.** cyrius 6.2.x only auto-associates a declared stdlib
  module when *first-party source* references it; modules referenced
  only inside a dep bundle no longer get pulled. Nothing in phylax's own
  source calls `thread_local_*` — only the bundled sigil `cbank` path
  does — so the `thread_local` declaration in `[deps] stdlib` (added in
  1.2.0) stopped pulling the module, its calls lowered to a `ud2`, and
  the first `sha256` SIGILLed. Fix: explicit `include "lib/thread_local.cyr"`
  at the top of `src/lib.cyr` and `src/lib_core.cyr` (sigil's documented
  opt-in pattern — "cyrius stdlib is opt-in, not auto-associated").
  `tests/test_sha256.tcyr` passes again (`e3b0c442…` empty-string vector
  + determinism); the build emits zero `undefined function` warnings.
  (`thread` still auto-associates via `cli.cyr`'s `thread_create` use, so
  only `thread_local` needs the explicit include.)

- **Stale sigil 3.7.8 bundle no longer builds under 6.2.x.** The 3.7.8
  `dist/sigil.cyr` carried un-inlined `include "src/*.cyr"` lines (the
  distlib-inliner bug fixed in sigil 3.7.11), which fail under 6.2.x with
  `cannot open include file: src/sha_ni.cyr`. Bumping to sigil 3.8.0 (a
  properly inlined bundle) is what makes the toolchain bump build at all.

### Note for consumers

`dist/phylax.cyr` / `dist/phylax-core.cyr` are pure source concatenations
and do not embed stdlib. Downstream consumers that reach phylax's
`sha256` path (daimon, aegis, t-ron) must, like all sigil consumers on
cyrius ≥ 6.2.x, `include "lib/thread_local.cyr"` themselves alongside the
sigil bundle — the same opt-in they already owe for the rest of the
stdlib surface.

## [1.2.0] - 2026-06-10

Toolchain + dep pin sweep onto the cyrius 6.1.x line, including the
**bayan stdlib carve** migration. No detection behavior changes in
`src/`; the only source edit is the engine version string. The bump
surfaced two build-breaks the sweep resolves — a `sha256` SIGILL and the
carved-out data-format modules — both in **Fixed**.

### Changed

- **Cyrius toolchain pin: 5.10.44 → 6.1.27.** Moves phylax onto the
  6.1.x frontend/codegen line, crossing three relevant slots: **6.1.25**
  (the bayan data-format carve — see the `[deps]` reshape below),
  **6.1.26** (the ganita math carve — a no-op for phylax, which uses only
  the stdlib `math` primitive `f64_log2` in `shannon_entropy`; the carved
  matrix/linalg/transcendental surface is unused, so no `ganita` dep is
  added), and **6.1.27** (binary output cap raised 2 MB → 16 MB). `lib/`
  is a derived artifact, rehydrated by `cyrius deps` against the pinned
  toolchain snapshot (stdlib) plus the pinned git bundles; the dep
  contract is `cyrius.cyml` + `cyrius.lock`.

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
