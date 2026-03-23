# Architecture Overview

## Design Principles

1. **Single crate** — flat module layout, no workspace overhead
2. **Zero unsafe code** — memory safety throughout
3. **Extensible rules** — YARA-compatible TOML rule format
4. **AI-native** — designed for daimon orchestration and hoosh LLM triage
5. **MCP via bote** — tool registration handled by the bote MCP crate

## Module Map

```
src/
├── core.rs       Types: ScanTarget, ThreatFinding, ScanResult, ScanConfig
├── error.rs      PhylaxError enum
├── yara.rs       Rule engine: literal, hex, regex patterns
├── analyze.rs    Entropy, magic bytes, SHA-256, polyglot detection
├── ai.rs         Agent registration, hoosh triage types
└── daimon.rs     Daimon orchestrator HTTP client
```

## Scan Pipeline

1. **File I/O** — read file, enforce `max_file_size`
2. **Magic bytes** — identify file type from header bytes
3. **SHA-256** — compute content hash
4. **Entropy** — Shannon entropy + block profile, flag suspicious (>7.5 bits/byte)
5. **Polyglot** — detect files matching multiple format signatures
6. **YARA scan** — match loaded rules against content
7. **Aggregate** — merge findings, sort by severity, report

## Consumers

- **daimon** — orchestrator registers phylax as a threat-scanning agent
- **hoosh** — LLM triage classifies findings for analyst review
- **bote** — MCP protocol layer registers phylax tools for external access
