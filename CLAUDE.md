# Phylax — Claude Code Instructions

## Project Identity

**Phylax** (Greek: guardian/watchman) — Threat detection — YARA rules, entropy, magic bytes, PE/ELF parsing, binary classification

- **Language**: Cyrius 5.1.3
- **Type**: Flat binary (single src/main.cyr)
- **License**: GPL-3.0-only
- **Version**: SemVer 0.D.M pre-1.0
- **Ported from**: 14,133 lines of Rust (preserved in rust-old/)
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)
- **Recipes**: [zugot](https://github.com/MacCracken/zugot) — takumi build recipes

## Build

```bash
cyrius build src/main.cyr build/phylax    # compile
cyrius test tests/phylax.tcyr             # run tests
cyrius bench tests/phylax.bcyr            # benchmarks
cyrius check src/main.cyr                 # syntax check
cyrius fmt src/main.cyr                   # format
cyrius lint src/main.cyr                  # lint
```

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
- **sakshi on all operations** — structured logging for audit trail.
- **Manual memory management** — alloc what you need, no hidden allocations.

## Source Structure

```
src/main.cyr          — Complete engine (7098 lines, flat binary)
rust-old/src/         — Original Rust source (14,133 lines, preserved for reference)
tests/phylax.tcyr     — Test suite
tests/phylax.bcyr     — Benchmarks
tests/phylax.fcyr     — Fuzz harness
```

### Module Map (within src/main.cyr)

| Section | Lines | Description |
|---------|-------|-------------|
| Constants/Enums | ~230 | Severity, category, file type, error codes |
| Structs | ~200 | ThreatFinding, ScanResult, ScanConfig, BinaryAnalysis |
| Entropy/Analysis | ~400 | Shannon entropy, chi-squared, file detection, polyglot |
| Strings | ~150 | ASCII + UTF-16 LE extraction |
| Script Analysis | ~250 | Language classification, obfuscation detection |
| SSDEEP | ~300 | Context-triggered piecewise hashing |
| TLSH | ~300 | Locality sensitive hashing |
| PE Parser | ~1000 | DOS/COFF/Optional headers, imports, exports, TLS, Rich header |
| ELF Parser | ~600 | 32/64-bit, sections, segments, security features |
| YARA Engine | ~1400 | Pattern matching, TOML/yar parsers, condition evaluation |
| Queue | ~120 | Priority scan queue |
| Quarantine | ~250 | File isolation with index persistence |
| Report | ~300 | JSON, Markdown, SARIF v2.1.0 output |
| Hoosh Client | ~150 | LLM triage (synchronous HTTP) |
| Daimon Client | ~120 | Agent orchestrator registration |
| Bote MCP Tools | ~120 | 5 MCP tool definitions + 2 handlers |
| CLI | ~500 | Argument parsing, subcommands, scan pipeline |

## Dependencies (cyrius.cyml)

- **stdlib**: string, fmt, alloc, vec, str, syscalls, io, args, assert, hashmap, json, toml, regex, fs, net, tagged, fnptr, callback, thread, bench, bounds, math, process, chrono, base64, csv
- **sakshi** 1.0.0 — structured logging
- **sigil** 2.1.2 — cryptographic primitives (SHA-256)
- **bote** 2.5.1 — MCP tool registry and dispatch

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
