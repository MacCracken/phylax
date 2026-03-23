# Phylax

**AI-native threat detection engine for AGNOS.**

> **Name**: Phylax (Greek: φύλαξ) — guardian, watchman. Real-time threat detection with YARA rules, binary analysis, and LLM-assisted triage.

[![CI](https://github.com/MacCracken/phylax/actions/workflows/ci.yml/badge.svg)](https://github.com/MacCracken/phylax/actions/workflows/ci.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

---

## Capabilities

| Capability | Details |
|------------|---------|
| **YARA rules** | Literal, hex, regex patterns; TOML rule format; All/Any/AtLeast conditions; file size + offset constraints |
| **Entropy analysis** | Shannon entropy, block profiling, suspicious threshold (>7.5 bits/byte) |
| **Magic bytes** | ELF, PE, Mach-O, PDF, ZIP, GZIP, PNG, JPEG, Script detection |
| **Binary parsing** | PE headers (sections, imports, exports); ELF headers (sections, symbols, DT_NEEDED) |
| **String extraction** | ASCII + UTF-16 LE with configurable minimum length |
| **Polyglot detection** | Files matching multiple format signatures |
| **Severity escalation** | Auto-escalation based on combined signals |
| **Watch mode** | inotify/kqueue filesystem monitoring with auto-scan |
| **LLM triage** | Findings sent to hoosh for classification via `/v1/chat/completions` |
| **MCP tools** | Bote integration for tool registry (feature-gated) |
| **Daemon** | Unix socket listener with daimon lifecycle (register, heartbeat, deregister) |
| **Reports** | JSON and Markdown threat reports with severity summary |
| **Quarantine** | File quarantine/release with persistent index |

## Modules

| Module | Description |
|--------|-------------|
| `core` | ScanTarget, FindingSeverity, ThreatFinding, ScanResult, ScanConfig, PhylaxError |
| `error` | PhylaxError enum with thiserror |
| `yara` | YARA rule engine — patterns, conditions, constraints, TOML loading |
| `analyze` | Entropy, magic bytes, SHA-256, polyglot detection, severity escalation |
| `pe` | PE header parsing — sections, imports, exports |
| `elf` | ELF parsing — 32/64-bit, sections, symbols, dynamic libraries |
| `strings` | ASCII + UTF-16 LE string extraction |
| `hoosh` | HooshClient — LLM triage via hoosh chat completions API |
| `daimon` | DaimonClient — agent registration, heartbeat loop, deregistration |
| `ai` | AgentRegistration, capability constants |
| `queue` | Priority scan queue (bounded, thread-safe) |
| `quarantine` | File quarantine/release with persistent JSON index |
| `report` | ThreatReport generation (JSON, Markdown) |
| `watch` | Filesystem watch mode (inotify/kqueue/FSEvents) |
| `bote_tools` | Bote MCP tool registration (feature-gated) |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `bote` | No | Enable bote MCP tool registration |

## Quick Start

```bash
# Scan a file
phylax scan /path/to/suspicious.bin

# Scan a directory (recursive)
phylax scan /var/uploads/

# Scan with YARA rules + LLM triage
phylax scan /path/to/file --rules threats.toml --triage

# Watch a directory for changes
phylax watch /opt/artifacts --extensions bin,exe,dll --triage

# Generate a report
phylax report /path/to/file -f markdown

# Run as daemon with orchestrator registration
phylax daemon --register --daimon-url http://daimon:8090 --triage

# List YARA rules
phylax rules list --file threats.toml

# Enable debug logging
PHYLAX_LOG=debug phylax scan /path/to/file
```

## YARA Rules Format

```toml
[[rule]]
name = "detect_elf"
description = "Detects ELF binaries"
severity = "medium"
tags = ["elf", "linux"]
condition = "any"
min_file_size = 4

[[rule.patterns]]
id = "$magic"
type = "hex"
value = "7f454c46"
```

Pattern types: `literal`, `hex`, `regex`. Conditions: `all`, `any`, `at_least_N`. Constraints: `min_file_size`, `max_file_size`, `at_offset`.

## Building

```bash
make check          # fmt + clippy + test + audit
make build          # release build
make bench          # 16 benchmark groups
make bench-history  # CSV + 3-run Markdown tracking
make coverage       # HTML coverage report
```

231 tests (221 unit + 10 integration) · 16 benchmark groups · 3 fuzz targets · 13 proptest property tests

## License

GPL-3.0
