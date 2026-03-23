# Changelog

All notable changes to Phylax will be documented in this file.

## [0.3.0] - 2026-03-22

### Added
- `pe` module: PE header parsing — DOS/COFF/optional headers, section table, import/export directory extraction
- `elf` module: ELF header parsing — 32/64-bit, section headers, `.dynsym` symbol extraction, `DT_NEEDED` dynamic library dependencies
- `strings` module: ASCII and UTF-16 LE string extraction from binary data with configurable minimum length
- `RuleConstraints`: YARA rules now support `min_file_size`, `max_file_size`, and `at_offset` constraints in TOML
- `escalate_severity()`: auto-escalates finding severity based on combined signals (entropy+polyglot=Critical, executable+Medium=High, multiple signals=escalate)
- `findings_from_analysis()`: accepts pre-computed `BinaryAnalysis` to avoid redundant computation
- 14 benchmark groups (added: strings, pe_parse, elf_parse)
- 143 tests (139 unit + 4 integration)

### Changed
- `YaraEngine::scan()` now checks `RuleConstraints` before pattern matching
- `YaraRule` struct now includes `constraints: RuleConstraints` field

## [0.2.0] - 2026-03-22

### Changed
- **BREAKING**: Flattened from workspace (5 crates) to single crate with flat `src/` layout
- **BREAKING**: Removed `phylax-mcp` crate — MCP tool registration now handled by [bote](https://github.com/MacCracken/bote)
- **BREAKING**: `YaraPattern::Regex` now stores compiled `Regex` instead of `String` (no longer `Serialize`/`Deserialize`)
- `cmd_scan` no longer double-computes entropy, SHA-256, and file type detection
- `hex_encode` uses `write!` instead of per-byte `format!` allocation
- Entropy profile `max_by` uses `total_cmp` instead of `partial_cmp().unwrap()` (NaN-safe)

### Added
- `#[non_exhaustive]` on all 7 public enums
- `YaraPattern::regex()` constructor that compiles and caches regex at creation time
- `DaimonClient::heartbeat()` validates `agent_id` (rejects empty, `/`, `\`)
- `PHYLAX_LOG` env var for log filtering (falls back to `RUST_LOG`, defaults to `warn`)
- `tracing` instrumentation on `YaraEngine::scan`, `load_rules_toml`, `analyze`, `analyze_findings`
- 86 unit tests + 4 integration tests (90 total)
- 8 benchmark groups with throughput measurement (entropy, profile, file detection, SHA-256, analyze, YARA, full pipeline, entropy quality)
- `scripts/bench-history.sh` — benchmark runner with CSV history + 3-run Markdown tracking
- 3 fuzz targets: `fuzz_yara`, `fuzz_analyze`, `fuzz_entropy`
- `examples/scan_file.rs`
- GitHub Actions CI (9 jobs: check, security, deny, test x3 OS, MSRV, coverage, benchmarks, doc, semver)
- GitHub Actions release workflow (version verification, crates.io publish, GitHub release)
- `scripts/version-bump.sh`
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `codecov.yml`
- `supply-chain/` (cargo-vet config and audits)
- `docs/` (architecture overview, threat model, roadmap, testing guide)

### Removed
- `phylax-mcp` crate (MCP tool definitions — use bote instead)
- `target/` directory from git tracking

## [0.1.0] - 2026-03-22

### Added
- Initial release of the Phylax threat detection engine
- Core types: ScanTarget, FindingSeverity, FindingCategory, ThreatFinding, ScanResult, ScanConfig, PhylaxError
- YARA-compatible rule engine with literal, hex, and regex pattern matching; TOML rule loading; All/Any/AtLeast conditions
- Shannon entropy calculation, entropy profiling, magic bytes detection (ELF, PE, Mach-O, PDF, ZIP, GZIP, PNG, JPEG, Script), polyglot file detection, SHA-256 hashing, binary analysis
- Daimon agent registration client, hoosh LLM triage request/response types
- CLI with `scan`, `daemon`, `rules list`, and `status` subcommands
