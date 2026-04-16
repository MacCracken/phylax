# Architecture Overview

## Design Principles

1. **Single flat binary** — all code in `src/phylax.cyr`, compiled to one static ELF
2. **Zero external runtime** — Cyrius 5.1.7, no libc, no LLVM, no interpreter
3. **Extensible rules** — YARA-compatible TOML + native .yar syntax with module conditions
4. **AI-native** — hoosh LLM triage, daimon orchestration, bote MCP tools
5. **Watch-first** — inotify filesystem monitoring for real-time detection
6. **Defense in depth** — O_NOFOLLOW, fstat, allocation limits, bomb protection

## Source Layout

```
src/
├── phylax.cyr       Library (8,500+ lines — all modules)
└── main.cyr         Entry point (includes phylax.cyr)

tests/
├── phylax.tcyr      Test suite (120+ assertions)
├── phylax.bcyr      Benchmarks (12 groups)
└── phylax.fcyr      Fuzz harness

```

## Module Map (within phylax.cyr)

```
Constants & Enums ─── Severity, Category, FileType, Error codes
        │
Structs ──────────── ThreatFinding, ScanResult, ScanConfig, BinaryAnalysis,
        │             Baseline, ScanTarget
        │
Utilities ────────── hex_encode, memmem, str_lower, str_to_cstr, phylax_alloc,
        │             phylax_read_file (mmap + O_NOFOLLOW), phylax_timestamp
        │
Analysis ─────────── shannon_entropy, chi_squared, classify_randomness,
        │             detect_file_type (10 formats), detect_polyglot,
        │             sha256 (via sigil), escalate_severity, section_entropy
        │
Strings ──────────── extract_ascii, extract_utf16le, extract_strings
        │
Script ───────────── classify_script (6 languages), detect_obfuscation,
        │             per-language patterns (PowerShell, VBScript, JavaScript)
        │
Similarity ───────── ssdeep_hash, ssdeep_compare (CTPH),
        │             tlsh_hash, tlsh_distance (locality-sensitive)
        │
Archives ─────────── zip_scan_entries (stored), gzip_scan, tar_scan_entries,
        │             detect_tar, bomb protection (depth/entries/expand limits)
        │
PE Parser ────────── parse_pe: DOS/COFF/Optional, sections (96 cap),
        │             imports (256 cap) + ILT, exports (1024 cap),
        │             TLS callbacks, PDB path, Rich header, imphash,
        │             resources, Authenticode, rich_product_name
        │
ELF Parser ───────── parse_elf: 32/64-bit, LE/BE, sections (1024 cap),
        │             segments, DT_NEEDED, symbols (4096 cap),
        │             interpreter, security (RELRO, RWX, stack exec)
        │
YARA Engine ──────── Pattern matching (literal, hex, string, nocase),
        │             TOML + .yar parsers, condition AST evaluation,
        │             module conditions (pe.*, elf.*),
        │             7 built-in rules, Aho-Corasick threshold
        │
Queue ────────────── Binary heap priority queue (O(log n))
        │
Quarantine ───────── File isolation, JSON index, path traversal rejection
        │
Report ───────────── JSON, Markdown (pipe escaping), SARIF v2.1.0
        │
Integration ──────── hoosh (HTTP POST triage), daimon (register/heartbeat),
        │             bote MCP (5 tools, 2 handlers)
        │
CLI ──────────────── scan, report, watch, daemon, rules (list/validate/fetch),
                      intel (import), status, help
                      Config file (phylax.toml), progress indicator
```

## Scan Pipeline

```
File Path
    │
    ▼
┌─────────────────┐
│ phylax_read_file │ ← mmap (>64KB) or alloc+read (<64KB)
│ O_NOFOLLOW       │ ← symlink rejection
│ fstat            │ ← regular file check
│ alloc limit      │ ← 200MB per-scan cap
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Binary Analysis  │ ← entropy, chi-squared, magic bytes, SHA-256
│ detect_file_type │ ← u32 compare (10 formats)
│ detect_polyglot  │ ← embedded signatures
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ YARA Engine      │ ← pattern matching + condition evaluation
│ builtin rules    │ ← 7 default detection rules
│ module conditions│ ← pe.is_dll, elf.machine, filesize
│ custom .yar/.toml│ ← user-supplied rules
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Escalation       │ ← entropy+polyglot→Critical, executable→High
│ Archive Scan     │ ← ZIP stored, TAR, GZIP (recursive, depth 3)
│ Baseline Filter  │ ← .phylax-ignore suppression
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Output           │ ← CLI findings, JSON report, Markdown, SARIF
│ Triage (optional)│ ← hoosh LLM classification
│ Fingerprint      │ ← SHA-256 dedup for baseline
└─────────────────┘
```

## Dependencies

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Cyrius stdlib | 5.1.7 | 29 modules (string, vec, hashmap, io, fs, net, json, toml, ...) |
| sakshi | 1.0.0 | Structured logging |
| sigil | 2.1.2 | SHA-256 cryptographic hashing |
| bote | 2.5.1 | MCP tool registry and JSON-RPC dispatch |
| majra | 2.2.0 | Pub/sub events (bote dependency) |

## Consumers

| Project | Integration |
|---------|-------------|
| **daimon** | Orchestrator — phylax registers as threat-scanning agent |
| **hoosh** | LLM gateway — triage findings via chat completions |
| **bote** | MCP protocol — 5 registered tools for external access |
| **aegis** | Quarantine — file isolation on threat detection |
| **t-ron** | Complement — output scanning for generated content |

## Memory Model

- **Heap**: Cyrius bump allocator (~21MB) for small objects (<64KB)
- **mmap**: `mmap_anon` for large allocations (≥64KB) — OS virtual memory
- **mmap I/O**: `mmap_file_ro` for files >64KB — zero-copy scanning
- **Per-scan limit**: 200MB total allocation cap per file
- **YARA engine**: Global singleton, created once, reused across all scans

## Security Hardening

| Layer | Mechanism |
|-------|-----------|
| File open | `O_NOFOLLOW` rejects symlinks |
| File verify | `fstat` confirms regular file |
| Size limits | 100MB file cap, 200MB alloc cap |
| Archive bombs | Depth 3, 1024 entries, 100MB expand |
| Path traversal | Quarantine ID validation, agent ID validation |
| Pattern DoS | 4096 max match offsets |
| PE/ELF caps | 96 sections (PE), 1024 sections (ELF), 4096 symbols |
| Daemon | Single-threaded, per-connection isolation |
