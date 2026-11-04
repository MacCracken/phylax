# Phylax — Claude Code Instructions

## Project Identity

**Phylax** (Greek: guardian/watchman) — Threat detection — YARA rules, entropy, magic bytes, PE/ELF parsing, binary classification

- **Language**: Cyrius 6.7.9
- **Type**: Modular CLI binary + library (`[lib]` / `[lib.core]` profiles)
- **License**: GPL-3.0-only
- **Version**: SemVer 0.D.M pre-1.0
- **Ported from**: 14,133 lines of Rust (original source removed at 0.98.0)
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)
- **Recipes**: [zugot](https://github.com/MacCracken/zugot) — takumi build recipes

## Build

```bash
CYRIUS_DCE=1 cyrius build src/main.cyr build/phylax  # compile (DCE-pruned)
for t in tests/*.tcyr; do cyrius test "$t"; done     # full suite — per-module test files
for t in tests/*.tcyr; do cyrius test --aarch64 "$t"; done  # same suite on aarch64 (runs under qemu-aarch64)
CYRIUS_DCE=1 cyrius build --aarch64 src/main.cyr build/phylax-aarch64
cyrius deps --locked                                 # lock check: tags vs cyrius.lock (+ lib/ bytes), writes nothing
cyrius test tests/test_severity.tcyr                 # single module (per-module split lands at 1.1.1)
cyrius test tests/phylax-core.tcyr                   # core profile smoke test (11 assertions)
cyrius bench tests/phylax.bcyr                       # full benchmarks
cyrius bench tests/phylax-core.bcyr                  # core benchmarks
cyrius check src/main.cyr                            # syntax check
cyrius fmt src/main.cyr                              # format
cyrius lint src/main.cyr                             # lint
cyrius distlib                                       # → dist/phylax.cyr (full lib)
cyrius distlib core                                  # → dist/phylax-core.cyr (detection-only)
cyrius distlib --all                                 # both profiles at once
cyrius distlib --check                               # CI gate: stale or refused → exit 1, writes nothing
cyrius fmt --check <file>                            # drift gate (bare `fmt` rewrites in place)
```

From cyrius 6.6.18 `distlib` compile-verifies each bundle on six targets (incl.
aarch64) and derives the `dist/*.deps` sidecar ONLY from that — not from
`[deps] stdlib`. A lib leaf a bundled module needs only on another target must be
an explicit `include "lib/X.cyr"` in that module (see the `lib/math.cyr` include
at the top of `src/analyze.cyr`), or distlib refuses and writes no sidecar.

The test suite is split per-module under `tests/test_*.tcyr` (18 files, plus
`tests/phylax-core.tcyr`; 441 assertions total as of 1.3.0, on x86_64 AND aarch64) so a
crash in one module doesn't poison the rest of the run. Add a new module's tests as
`tests/test_<module>.tcyr`; CI picks up `tests/*.tcyr` automatically.

`tests/test_cli.tcyr` is the one file that includes `src/cli.cyr` on top of
`src/lib.cyr` — its `main()` shadows cli.cyr's. That is what makes the argv-facing
subcommand helpers testable; put CLI-boundary tests there.

## Consumers

daimon (scan integration), aegis (quarantine), t-ron (output scanning complement)

## Development Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, and open issues — know what was intended before auditing what was built
1. Test + benchmark sweep of existing code
2. Cleanliness check: `cyrius fmt --check`, `cyrius lint`, `cyrius vet`, `cyrius deny`
3. Get baseline benchmarks (`cyrius bench`)
4. Initial refactor + audit (performance, memory, security, edge cases)
5. Cleanliness check — must be clean after audit
6. Additional tests/benchmarks from observations
7. Post-audit benchmarks — prove the wins
8. Repeat audit if heavy
9. Documentation audit — ADRs, source citations, guides, examples (see Documentation Standards in first-party-standards.md)

### Development Loop (continuous)

1. Work phase — new features, roadmap items, bug fixes
2. Cleanliness check: `cyrius fmt --check`, `cyrius lint`, `cyrius vet`, `cyrius deny`
3. Test + benchmark additions for new code
4. Run benchmarks (`cyrius bench`)
5. Audit phase — review performance, memory, security, throughput, correctness
6. Cleanliness check — must be clean after audit
7. Deeper tests/benchmarks from audit observations
8. Run benchmarks again — prove the wins
9. If audit heavy → return to step 5
10. Documentation — update CHANGELOG, roadmap, docs, ADRs for design decisions, source citations for algorithms/formulas, update docs/sources.md, guides and examples for new API surface, verify recipe version in zugot
11. Version check — VERSION, cyrius.cyml, recipe (in zugot) all in sync
12. Return to step 1

### Key Principles

- **Never skip benchmarks.** Numbers don't lie. The CSV history is the proof.
- **Tests + benchmarks are the way.** Minimum 80%+ coverage target.
- **Own the stack.** If an AGNOS project wraps an external lib, depend on the AGNOS project.
- **No magic.** Every operation is measurable, auditable, traceable.
- **Bounds check all buffer access** — `load8/16/32/64` must verify offset < data_len.
- **No raw syscall without validation** — sanitize paths, IDs, sizes before use.
- **Never define a `SYS_*` / `O_*` / `STAT_*` / `IN_*` constant — take the stdlib's.** The stdlib
  defines them per target, and a phylax global of the same name wins PROGRAM-WIDE (inside the
  stdlib's own wrappers too). x86 values defined in `src/types.cyr` broke `phylax watch` and the
  symlink refusal on aarch64 until 1.3.0 while every x86 test passed. Call the stdlib's `sys_*`
  wrappers rather than `syscall(N, …)`; the x86 arch macro is `CYRIUS_ARCH_X86` (there is no
  `CYRIUS_ARCH_X86_64`). Run the suite with `--aarch64` before claiming portability.
- **Define no bare name the stdlib defines** (ADR 0002). A const/var collision is a hard error in a
  consumer (1.3.0: `F64_255` vs mabda's `const`). Prefix phylax-only names `PHYLAX_` / `phylax_`.
- **sakshi on all operations** — structured logging for audit trail.
- **Manual memory management** — alloc what you need, no hidden allocations.

## Source Structure

```
src/main.cyr          — CLI entry point (includes lib.cyr + cli.cyr)
src/lib.cyr           — full library include list, matches [lib] profile
src/lib_core.cyr      — detection-only include list, matches [lib.core] profile
src/<module>.cyr      — 17 modules (types, utils, analyze, strings, script, hashing,
                        pe, elf, archive, yara, queue, quarantine, report,
                        integration, cli)
tests/test_*.tcyr     — per-module test files (18 files + phylax-core, 441 assertions)
tests/phylax-core.tcyr — [lib.core] smoke test (proves core compiles standalone)
tests/phylax.bcyr     — full benchmarks
tests/phylax-core.bcyr — [lib.core] benchmarks
tests/phylax.fcyr     — fuzz harness
dist/phylax.cyr       — generated by `cyrius distlib` from [lib]
dist/phylax-core.cyr  — generated by `cyrius distlib core` from [lib.core]
```

### Module Map (in src/)

| Module | Profile | Description |
|--------|---------|-------------|
| `types.cyr` | core+full | Severity/category/filetype enums, structs (ScanTarget, Finding, ScanResult, BinaryAnalysis), error codes, init |
| `utils.cyr` | core+full | memmem, hex codec, byte helpers, `in_bounds` offset validator |
| `analyze.cyr` | core+full | Shannon entropy, chi-squared, file detection (magic bytes), polyglot |
| `strings.cyr` | core+full | ASCII + UTF-16 LE extraction |
| `script.cyr` | core+full | Script language classification, obfuscation detection |
| `hashing.cyr` | core+full | SHA-256 (via sigil), SSDEEP, TLSH |
| `pe.cyr` | core+full | DOS/COFF/Optional headers, imports, exports, TLS, Rich header |
| `elf.cyr` | core+full | 32/64-bit, sections, segments, security features |
| `archive.cyr` | core+full | TAR/ZIP/GZIP archive scanning, bomb protection |
| `yara.cyr` | core+full | Pattern matching, TOML/yar parsers, condition evaluation |
| `report.cyr` | core+full | JSON, Markdown, SARIF v2.1.0 output |
| `queue.cyr` | full only | Priority scan queue (runtime) |
| `quarantine.cyr` | full only | File isolation with index persistence (runtime) |
| `integration.cyr` | full only | bote MCP tools, daimon agent register, hoosh LLM triage |
| `cli.cyr` | binary only | Argument parsing, subcommands, scan pipeline |

## Dependencies (cyrius.cyml)

- **stdlib**: string, fmt, alloc, vec, str, syscalls, io, args, assert, hashmap, regex, fs, net, tagged, fnptr, atomic, sync, thread, bench, bounds, math, process, chrono, freelist, http, mmap, ct, keccak, random, slice, thread_local, **bayan** (cyrius 6.1.25 carve — supplies json/toml/csv/base64/bigint/cyml/u128 via back-compat aliases), **sakshi**, **sigil**

### Folded stdlib modules (NOT git deps)

- **sakshi** 2.5.8 — structured logging. Folded into the toolchain snapshot (since the 6.5.18 line).
- **sigil** 3.13.11 — cryptographic primitives (SHA-256, SHA-NI dispatch). Folded.
- **bayan** 1.5.13 — json/toml/csv/base64/bigint. Folded. (Versions are what cyrius 6.7.9 vendors.)

⚠ All three are declared in `[deps] stdlib`, **not** as `[deps.X]` git blocks, and must stay that way.
`cyrius distlib` classifies a git dep out of the stdlib leaves, so a folded module declared as a git
dep is dropped from the sidecars and consumers can link with `sha256_*` / `sakshi_*` undefined. A git
dep also *overlays* the snapshot, so a lagging pin silently downgrades a folded module. The `cyrius`
pin is the only knob that moves them.

Comments inside the `stdlib` array were parsed, not skipped, through cyrius 6.6.16 (a `[` truncated
the array, a `"quoted phrase"` became a module). 6.6.17 fixed that; long rationale still lives below
the closing `]` by convention.

### Git deps

⚠ **No `path = "../X"` lines committed.** Through cyrius 6.6.x a `path` beside `git`/`tag` won
whenever the sibling checkout existed (vendored its working tree, rewrote `cyrius.lock`) while CI
built the tag. From 6.7.6 (pinned since 1.3.0) a path is read only in local mode
(`CYRIUS_LOCAL=1`, resolving into `build/local-deps/lib/`), so a default build always sees the tag —
keep it that way. Pick each tag as the newest published one whose own `cyrius` pin matches
phylax's, and confirm it on GitHub (curl the API; ssh is unavailable in the sandbox).

⚠ **DCE compaction cap (cyrius < 6.7.14).** Past 4,096 dead-code runs, `CYRIUS_DCE=1` declines to
compact and the binary keeps the NOPed bytes (1.3.0: 866 KB → 2.36 MB, pushed over by bote-core
3.4.10's extra functions). Watch the "compaction declined" note on any dep bump.

- **majra** 2.12.0 — pubsub/counter; **vestigial** since bote-core dropped `events_majra` (phylax calls it directly nowhere) — staged, DCE-pruned, kept at bote's own majra pin pending a dep-pruning pass
- **bote** 3.4.10 — MCP tool registry and dispatch, consumed via the transport-free **`dist/bote-core.cyr`** bundle (the old 11 hand-picked `src/*.cyr` modules no longer link under bote 3.x)
- **libro** 2.11.0 — **vestigial** belt-and-suspenders pin aligned to bote 3.4.10's transitive libro; not referenced by phylax or bote-core (DCE-pruned). It still declares sigil as a *git* dep, but since cyrius 6.6.11 that is inert: `cyrius deps` no longer vendors a git dep's thin sigil files when `sigil` is a stdlib leaf (the ~350 KB / 232-warning double-stage of 1.2.5–1.2.7 is gone).

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, LICENSE

docs/ (required):
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — completed, backlog, future, v1.0 criteria

docs/ (when earned):
  adr/ — architectural decision records
  guides/ — usage guides, integration patterns
  examples/ — worked examples
  standards/ — external spec conformance
  compliance/ — regulatory, audit, security compliance
  sources.md — source citations for algorithms/formulas (required for science/math crates)
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). Performance claims MUST include benchmark numbers. Breaking changes get a **Breaking** section with migration guide.

## DO NOT
- **Do not commit or push** — the user handles all git operations (commit, push, tag)
- **NEVER use `gh` CLI** — use `curl` to GitHub API only
- Do not add unnecessary dependencies — keep it lean
- Do not skip benchmarks before claiming performance improvements
- Do not commit `build/` directory
