# Changelog

All notable changes to Phylax will be documented in this file.

## [0.22.4] - 2026-03-22

### Added
- `watch` module: filesystem watch mode using `notify` crate (inotify/kqueue/FSEvents)
- `phylax watch /path [--extensions bin,exe] [--triage]` CLI command
- Recursive directory monitoring with extension filtering, file size limits, debounce
- Auto-scan on file create/modify with full pipeline (YARA, analysis, escalation, optional triage)
- `WatchConfig`, `WatchEvent`, `WatchHandle` types
- Daimon agent lifecycle: `start_lifecycle()` registers, runs heartbeat loop, `shutdown()` deregisters
- `DaimonHandle` — background heartbeat task with graceful shutdown
- `DaimonClient::deregister()` — DELETE agent from daimon
- `phylax daemon --register --daimon-url` flags for orchestrator integration
- Daemon gracefully deregisters from daimon on shutdown
- Hoosh client 30s request timeout (was infinite)
- Watch debounce map periodic cleanup (prevents memory leak in long sessions)
- Watch tokio runtime reuse (created once, not per-triage)
- Removed dead `TriageRequest`/`TriageResponse` types from `ai.rs`
- Eliminated scan duplication in `cmd_scan` (now calls `run_scan`)
- 212 tests (208 unit + 4 integration)

## [0.22.3] - 2026-03-22

### Added

**Core engine:**
- Core types: ScanTarget, FindingSeverity, FindingCategory, ThreatFinding, ScanResult, ScanConfig, PhylaxError
- YARA-compatible rule engine with literal, hex, and regex pattern matching; TOML rule loading; All/Any/AtLeast conditions
- `RuleConstraints`: file size limits (`min_file_size`, `max_file_size`) and `at_offset` constraints
- Compiled regex caching — regex patterns compiled once at rule load time
- `#[non_exhaustive]` on all public enums

**Analysis:**
- Shannon entropy calculation with block profiling and suspicious threshold (>7.5 bits/byte)
- Magic bytes detection: ELF, PE, Mach-O, PDF, ZIP, GZIP, PNG, JPEG, Script
- Polyglot file detection (multiple format signatures in one file)
- SHA-256 hashing
- PE header parsing: DOS/COFF/optional headers, section table, import/export directories
- ELF parsing: 32/64-bit, section headers, `.dynsym` symbols, `DT_NEEDED` dynamic libraries
- String extraction: ASCII and UTF-16 LE with configurable minimum length
- `escalate_severity()`: auto-escalation based on combined signals (entropy+polyglot=Critical, executable+Medium=High)
- `findings_from_analysis()`: accepts pre-computed analysis to avoid redundant computation

**Infrastructure:**
- Priority scan queue with bounded capacity and FIFO within same priority
- Quarantine directory management with persistent JSON index and SHA-256 tracking
- Threat report generation in JSON and Markdown formats
- Full daemon mode with Unix socket listener, path canonicalization, line length limits
- `phylax report` CLI command (JSON/Markdown output)

**Integrations:**
- Hoosh LLM triage client: sends findings to `/v1/chat/completions`, parses classification/confidence
- Bote MCP tool registration (feature-gated): phylax_scan, phylax_rules, phylax_status, phylax_quarantine, phylax_report
- Daimon agent registration and heartbeat client with path traversal validation

**Observability:**
- `PHYLAX_LOG` env var for log filtering (falls back to `RUST_LOG`, defaults to `warn`)
- `tracing` instrumentation on scan, analysis, YARA, and hoosh paths

**Quality:**
- 186+ unit tests + 4 integration tests
- 16 benchmark groups with throughput measurement
- 3 fuzz targets: YARA parsing, binary analysis, entropy
- `scripts/bench-history.sh` — CSV history + 3-run Markdown tracking
- GitHub Actions CI (9 jobs) + release workflow
- `cargo deny` + `cargo vet` supply chain verification
- SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, codecov.yml
- Documentation: architecture overview, threat model, testing guide
