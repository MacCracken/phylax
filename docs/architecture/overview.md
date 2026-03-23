# Architecture Overview

## Design Principles

1. **Single crate** — flat module layout, no workspace overhead
2. **Zero unsafe code** — memory safety throughout
3. **Extensible rules** — YARA-compatible TOML rule format with constraints
4. **AI-native** — hoosh LLM triage, daimon orchestration, bote MCP tools
5. **Watch-first** — filesystem monitoring for real-time threat detection

## Module Map

```
src/
├── main.rs          CLI (scan, daemon, watch, report, rules, status)
├── lib.rs           Public API root
│
├── core.rs          ScanTarget, FindingSeverity, ThreatFinding, ScanResult, ScanConfig
├── error.rs         PhylaxError enum
│
├── yara.rs          Rule engine — literal, hex, regex; constraints; TOML loading
├── analyze.rs       Entropy, magic bytes, SHA-256, polyglot, escalation
├── pe.rs            PE header parsing (sections, imports, exports)
├── elf.rs           ELF parsing (32/64-bit, sections, symbols, DT_NEEDED)
├── strings.rs       ASCII + UTF-16 LE string extraction
│
├── hoosh.rs         HooshClient — LLM triage via /v1/chat/completions
├── daimon.rs        DaimonClient — register, heartbeat loop, deregister
├── ai.rs            AgentRegistration, capability constants
├── bote_tools.rs    Bote MCP tool registration (feature-gated)
│
├── queue.rs         Priority scan queue (BinaryHeap, AtomicU64, bounded)
├── quarantine.rs    File quarantine/release with persistent JSON index
├── report.rs        ThreatReport generation (JSON, Markdown)
└── watch.rs         Filesystem watch (notify crate — inotify/kqueue/FSEvents)
```

## Scan Pipeline

1. **File I/O** — read file, enforce `max_file_size` (50 MB default)
2. **Binary analysis** — file type, entropy, SHA-256 in one pass
3. **Magic bytes** — identify file type from header (9 formats)
4. **Entropy** — Shannon entropy + block profile, flag suspicious (>7.5 bits/byte)
5. **Polyglot** — detect embedded format signatures
6. **YARA scan** — match loaded rules with constraint checks
7. **Escalation** — auto-escalate severity based on combined signals
8. **Triage** (optional) — send findings to hoosh for LLM classification

## Feature Flags

| Feature | Default | Dependencies | Description |
|---------|---------|-------------|-------------|
| `bote` | No | `bote 0.22` | MCP tool registration |

## Consumers

| Project | Integration |
|---------|-------------|
| **daimon** | Orchestrator — phylax registers as threat-scanning agent |
| **hoosh** | LLM gateway — triage findings via chat completions |
| **bote** | MCP protocol — registers phylax tools for external access |
