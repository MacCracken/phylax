# Phylax

**AI-native threat detection engine for AGNOS.**

> **Name**: Phylax (Greek: φύλαξ) — guardian, watchman. Real-time threat detection with YARA rules, binary analysis, and LLM-assisted triage.

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

---

## Capabilities

| Capability | Details |
|------------|---------|
| **YARA rules** | Literal, hex, regex patterns; TOML rule format; native .yar parser; All/Any/AtLeast conditions; file size + offset constraints; 7 built-in detection rules |
| **Entropy analysis** | Shannon entropy, chi-squared randomness test, block profiling, suspicious threshold (>7.5 bits/byte) |
| **Magic bytes** | ELF, PE, Mach-O, PDF, ZIP, GZIP, PNG, JPEG, Script detection |
| **Binary parsing** | PE headers (sections, imports, exports, Rich header, TLS callbacks, imphash); ELF headers (sections, symbols, DT_NEEDED, security features) |
| **String extraction** | ASCII + UTF-16 LE with configurable minimum length |
| **Script analysis** | 6-language classification (PowerShell, VBScript, JavaScript, Python, Batch, Shell) with obfuscation detection |
| **Similarity hashing** | SSDEEP (context-triggered piecewise) and TLSH (trend locality-sensitive) |
| **Polyglot detection** | Files matching multiple format signatures |
| **Severity escalation** | Auto-escalation based on combined signals |
| **Watch mode** | inotify filesystem monitoring with auto-scan |
| **LLM triage** | Findings sent to hoosh for classification via `/v1/chat/completions` |
| **MCP tools** | Bote integration — 5 tools, 2 handlers (always available) |
| **Daemon** | Unix socket listener with daimon lifecycle (register, heartbeat, deregister) |
| **Reports** | JSON, Markdown, and SARIF v2.1.0 threat reports with severity summary |
| **Quarantine** | File quarantine/release with persistent index |

## Modules (single src/main.cyr)

All 22 Rust modules ported into a single Cyrius source file:

| Module | Description |
|--------|-------------|
| `types` | ScanTarget, FindingSeverity, FindingCategory, ThreatFinding, ScanResult, ScanConfig — integer constants with helper functions |
| `error` | PhylaxError codes |
| `analyze` | Entropy, chi-squared, magic bytes, SHA-256, polyglot detection, severity escalation |
| `strings` | ASCII + UTF-16 LE string extraction |
| `script` | Script language classification and obfuscation detection |
| `ssdeep` | Context-triggered piecewise hashing with Levenshtein comparison |
| `tlsh` | Trend locality-sensitive hashing with Pearson hash table |
| `pe` | PE header parsing — sections, imports, exports, Rich header, TLS, imphash |
| `elf` | ELF parsing — 32/64-bit, sections, symbols, dynamic libraries, security features |
| `yara` | YARA rule engine — patterns, conditions, constraints, TOML loading |
| `yara_parser` | Native .yar lexer (33 token types) + recursive-descent parser |
| `queue` | Priority scan queue (vec-backed, capacity limited) |
| `quarantine` | File quarantine/release with JSON index persistence |
| `report` | ThreatReport generation (JSON, Markdown, SARIF) |
| `hoosh` | HooshClient — LLM triage via hoosh chat completions API |
| `daimon` | DaimonClient — agent registration, heartbeat, deregistration |
| `ai` | AgentRegistration, capability constants |
| `bote_tools` | Bote MCP tool registration — 5 tools, 2 handlers |
| `watch` | Filesystem watch mode via inotify syscalls |
| `main` | CLI entry point — scan, report, watch, rules, status |

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

# Validate YARA rules
phylax rules validate --file threats.yar

# Engine status
phylax status
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

Pattern types: `hex`, and `string` for a literal (in TOML rules every type other than `hex` is a literal — `regex` is not a regex there yet). Conditions: `all`, `any`, `at_least_N`. Constraints: `min_file_size`, `max_file_size`, `at_offset`.

Native `.yar` syntax is also supported via `phylax rules validate`.

## Building

Phylax is written in [Cyrius](https://github.com/MacCracken/cyrius) and compiles to a single static binary.

```bash
CYRIUS_DCE=1 cyrius build src/main.cyr build/phylax   # ~0.92 MB static binary (1.3.2)
for t in tests/*.tcyr; do cyrius test "$t"; done      # 483 assertions across 19 files
for t in tests/*.tcyr; do cyrius test --aarch64 "$t"; done   # the same suite on aarch64 (qemu)
cyrius bench tests/phylax.bcyr                        # benchmark groups
```

### Dependencies

- **Cyrius** 6.7.18 toolchain
- **stdlib** (34 modules): string, fmt, alloc, vec, str, syscalls, io, args, assert, hashmap, regex, fs, net, tagged, fnptr, atomic, sync, thread, bench, bounds, math, process, chrono, freelist, http, mmap, ct, keccak, random, slice, thread_local, bayan, sakshi, sigil — note `bayan` is the cyrius 6.1.25 carve that supplies the former `json`/`toml`/`csv`/`base64`/`bigint` stdlib modules
- **sakshi** 2.5.10 — structured logging (folded stdlib module, not a git dep)
- **sigil** 3.13.15 — SHA-256 (SHA-NI dispatch) (folded stdlib module, not a git dep)
- **bayan** 1.11.1 — JSON/TOML (folded stdlib module, not a git dep)
- **bote** 3.8.11 — MCP tool registry and dispatch (`dist/bote-core.cyr` transport-free bundle)
- **majra** 2.13.0 — pubsub/counter (vestigial since bote-core dropped `events_majra`; staged, DCE-pruned)
- **libro** 2.11.3 — belt-and-suspenders pin aligned to bote's transitive libro (DCE-pruned)

Targets: x86_64 Linux and aarch64 Linux (the full suite runs on both; aarch64 under qemu in CI).

Zero external runtime dependencies. No libc, no allocator, no async runtime.

### Rust source


## License

GPL-3.0
