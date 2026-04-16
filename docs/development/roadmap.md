# Roadmap

## Completed

### v0.7.5 — Cyrius Port (2026-04-16)

- Full port from Rust (14,133 lines) to Cyrius (7,323 lines)
- 86 tests passing across 16 test groups
- 804KB static binary, zero external runtime dependencies
- All 22 Rust modules ported: types, error, analyze, strings, script, ssdeep, tlsh, pe, elf, yara, yara_parser, queue, quarantine, report, hoosh, daimon, ai, bote_tools, watch, main
- Dependencies: 28 stdlib modules + sakshi 1.0.0 + sigil 2.1.2 + bote 2.5.1 + majra 2.2.0
- Toolchain: Cyrius 5.1.7
- CLI working: scan, status, help, report, watch, rules list/validate
- 7 built-in YARA detection rules
- Bote MCP tool registration (5 tools, 2 handlers)

## Backlog

### v0.8.0 — Feature Parity & Hardening

**YARA**
- YARA module system: `pe.is_dll`, `elf.machine` in condition expressions (evaluator exists, needs PE/ELF data wiring)
- `phylax rules fetch <source>` — download community rulesets

**Analysis**
- Archive recursive scanning (ZIP/GZIP/TAR) with bomb protection
- mmap I/O via `SYS_MMAP` for files > 1 MB (removes current heap limit)
- Parallel file scanning via `thread_create`

**Integration**
- HTTP POST implementation (raw socket) — enables hoosh LLM triage and daimon registration
- STIX/TAXII threat intel import (`phylax intel import --stix <file>`)
- MalwareBazaar SHA-256 hash feed (`phylax intel update`)

**UX / CLI**
- Config file support (`phylax.toml` / `$XDG_CONFIG_HOME/phylax/config.toml`)
- Progress indicator for multi-file scans
- `--severity-threshold` and `--exit-code` for CI/CD pipeline gating

**Hardening**
- `O_NOFOLLOW` + `fstat` in scan path
- Per-scan allocation limits
- Daemon mode with rate limiting

## v1.0 Criteria

- All v0.8.0 items complete
- Full YARA module system (pe, elf, math modules)
- 95%+ test coverage
- Benchmark parity with Rust (within 3x for core operations)
- Security audit complete
- Documentation: architecture, API reference, integration guide
- Stable CLI interface (no breaking changes after 1.0)

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
- WASM plugin system (reconsider post-v1)
