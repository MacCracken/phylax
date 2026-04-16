# Changelog

All notable changes to Phylax will be documented in this file.

## [0.8.3] - 2026-04-16

Archive scanning for ZIP and GZIP files.

### Archive Scanning
- **ZIP stored entry scanning** — walks local file headers, scans uncompressed (method 0) entries through full analysis + YARA pipeline
- **Recursive archive detection** — nested ZIP-in-ZIP scanned up to 3 levels deep
- **GZIP detection** — identifies GZIP archives, notes deflate decompression pending (v0.9)
- **Bomb protection** — max depth (3), max entries per archive (1024), max expanded size (100 MB)
- Wired into `run_scan` pipeline as Step 4 (after YARA, before result return)

### Tested
- Stored ZIP with clean content → 0 findings (correct)
- Stored ZIP with embedded ELF → 2 findings (polyglot + archive detection)
- GZIP file → 1 finding (compressed_archive informational)
- 86 tests passing

### Limitations
- Only stored (uncompressed) ZIP entries scanned — deflate decompression deferred to v0.9
- TAR format not yet supported

## [0.8.2] - 2026-04-16

Parallel file scanning for multi-file operations.

### Parallel Scanning
- **Thread pool** for multi-file scans — 4 worker threads via `thread_create`
- `parallel_scan_worker` processes file batches independently, results collected via mutex
- Automatically engages when scanning 4+ files; single-file scans remain sequential
- Added `str_to_cstr` helper for Str → null-terminated cstr conversion
- `PARALLEL_THREADS` and `PARALLEL_THRESHOLD` configurable constants

### Known Limitations
- Directory recursion with parallel scan needs cstr/Str unification (tracked for v0.9)
- `args.cyr` cmdline buffer on stack limits argv lifetime — affects path conversion

### Quality
- 86 tests passing
- 828KB static binary

## [0.8.1] - 2026-04-16

Memory-mapped I/O for large file scanning.

### mmap I/O
- **`mmap_file_ro`** for files > 64KB — zero-copy file access via `SYS_MMAP`, no heap pressure
- **`phylax_file_size`** — stat-based file size detection before read
- Small files (< 64KB) still use alloc+read for simplicity
- **100MB hard limit** (up from 1MB) — configurable via `PHYLAX_MAX_FILE_SIZE`
- Successfully scans 5MB+ files that previously crashed on heap exhaustion
- Added `mmap.cyr` stdlib dependency

### Quality
- 86 tests passing
- 828KB static binary
- Tested: 5-byte file (alloc path), 512KB file (mmap path), 5MB file (mmap path), 2MB PE-like file

## [0.8.0] - 2026-04-16

Feature parity release: YARA module conditions, CI pipeline gating, config file, timestamp formatting, and performance optimizations.

### YARA Module System
- **`pe.is_dll`, `pe.is_64bit`, `pe.machine`** — PE module field access in YARA condition expressions
- **`elf.machine`, `elf.type`** — ELF module field access in YARA conditions
- Scan engine now parses PE/ELF headers and passes module data through to condition evaluator
- `.yar` parser extended with dot-notation lexing for module field access

### CI/CD Pipeline Gating
- **`--severity-threshold`** flag (info/low/medium/high/critical) — minimum severity to trigger non-zero exit
- **`--exit-code`** flag — custom exit code when threshold met (default: 1)
- Note: exit code propagation affected by cc5 register spill in large functions — tracked for compiler fix

### Config File
- **`phylax.toml`** config file support — loads from `./phylax.toml` or `$HOME/.config/phylax/config.toml`
- Sections: `[scan]` (rules_path, max_file_size), `[hoosh]` (url), `[daimon]` (url)
- CLI flags override config file values

### Timestamp Formatting
- **`phylax_timestamp(epoch)`** — custom Gregorian calendar conversion (`YYYY-MM-DD HH:MM:SS`)
- Replaces stdlib `iso8601()` which hangs due to chrono.cyr division loop
- Status command and report timestamps now human-readable

### Performance
- **File detection: u32 compare** — single `read_u32_le` for 4-byte magic signatures instead of 4x `load8`
- **Queue: binary heap** — O(log n) enqueue/dequeue replacing O(n) sorted insert (was 200-364x slower than Rust)

### Quality
- 86 tests passing across 16 groups
- 828KB static binary (up from 811KB with new features)
- 7,818 lines of Cyrius (up from 7,515)
- Toolchain: Cyrius 5.1.7

## [0.7.5] - 2026-04-16

Full port from Rust to Cyrius. 14,133 lines of Rust → 7,098 lines of Cyrius (50% reduction). Zero external runtime dependencies — compiles to a single static binary.

### Breaking

- **Language change**: Rust → Cyrius 5.1.3. Build with `cyrius build` instead of `cargo build`.
- **Manifest change**: `Cargo.toml` → `cyrius.cyml`. Dependencies are now Cyrius stdlib modules + sakshi + sigil.
- **Async removed**: All async/tokio code replaced with synchronous equivalents. Hoosh and daimon clients use blocking HTTP.
- **Feature gates removed**: `bote` and `yara-x` optional features dropped. YARA-X backend not ported (native engine is sufficient).
- Original Rust source preserved in `rust-old/` for reference.

### Ported (all 22 Rust modules → single src/main.cyr)

**Core** (types, error, analyze, strings)
- All enum types as integer constants with name/rank helper functions
- 39 struct definitions with field accessors
- Shannon entropy, chi-squared, file type detection (9 formats), polyglot detection
- ASCII + UTF-16 LE string extraction
- SHA-256 via sigil dependency
- Severity escalation (entropy+polyglot, executable, multiple signals)
- Baseline suppression (fingerprint + rule name matching)

**Binary Parsing** (pe, elf)
- PE parser: DOS/COFF/Optional headers, sections (96 cap), imports (256 cap) with ILT/ordinal support, exports (1024 cap), TLS callback detection, PDB path, Rich header XOR decryption, resources, Authenticode certificates, imphash
- ELF parser: 32/64-bit, little/big-endian, sections (1024 cap), segments, DT_NEEDED, symbols (4096 cap), interpreter path, security features (RELRO, RWX, static linking, executable stack)

**Script Analysis** (script)
- 6-language classification (PowerShell, VBScript, JavaScript, Python, Batch, Shell)
- Obfuscation detection with per-line entropy + language-specific patterns

**Similarity Hashing** (ssdeep, tlsh)
- SSDEEP: rolling hash, FNV-1, context-triggered piecewise hashing, Levenshtein edit distance comparison
- TLSH: Pearson hash table, sliding window bucket filling, quartile encoding, distance function

**YARA Engine** (yara, yara_parser)
- Pattern matching: literal bytes, hex bytes, string patterns with nocase support
- TOML rule loader with severity, condition (all/any/at_least), constraints
- Native .yar parser: full lexer (33 token types) + recursive-descent parser
- Conditions: and/or/not, all/any/N of them, filesize comparisons, parenthesized expressions
- 7 built-in detection rules (PE, ELF, UPX, NOP sled, suspicious APIs, ransomware indicators, embedded PE)

**Infrastructure** (queue, quarantine, watch, report)
- Priority scan queue (vec-backed sorted insert, capacity limit)
- Quarantine with JSON index persistence, path traversal rejection, SYS_RENAME
- Directory watcher via inotify syscalls
- Report generation: JSON, Markdown (pipe escaping), SARIF v2.1.0

**Integration** (hoosh, daimon, ai)
- Hoosh LLM triage: synchronous HTTP POST, JSON/text response parsing
- Daimon agent lifecycle: register, heartbeat, deregister with ID validation
- Agent capabilities (11 items)

**Bote MCP Tools** (bote_tools — NEW in Cyrius port)
- 5 MCP tool definitions: phylax_scan, phylax_rules, phylax_status, phylax_quarantine, phylax_report
- 2 tool handlers: scan (file analysis → JSON response), status (engine info)
- Full JSON-RPC schema definitions with required/optional parameters
- Uses bote 2.5.1 registry + dispatcher API (was feature-gated in Rust, now always available)

**CLI** (main)
- Subcommands: scan, report, watch, rules list, rules validate, status
- Recursive file collection with symlink skip
- Full scan pipeline: read → analyze → YARA → escalate → report

### Dependencies (Cyrius)
- **stdlib** (25 modules): string, fmt, alloc, vec, str, syscalls, io, args, assert, hashmap, json, toml, regex, fs, net, tagged, fnptr, callback, thread, bench, bounds, math, process, chrono, base64, csv
- **sakshi** 1.0.0 — structured logging (replaces tracing/tracing-subscriber)
- **bote** 2.5.1 — MCP tool registry and dispatch (was feature-gated `bote` in Rust, now always included)
- **sigil** 2.1.2 — SHA-256 (replaces sha2)

### Removed (Rust-only dependencies no longer needed)
- aho-corasick, regex, memchr, serde, serde_json, tokio, reqwest, notify, clap, anyhow, thiserror, rayon, uuid, chrono (Rust), sha2, criterion, proptest, tempfile, yara-x (optional), bote (optional)

### Quality
- 16 test groups (526 lines) covering severity, errors, entropy, chi-squared, file detection, SHA-256, strings, PE parser, ELF parser, YARA, queue, SSDEEP, TLSH, memmem, hex encode, report
- 12 benchmark groups covering entropy, chi-squared, file detection, SHA-256, memmem, hex encode, string extraction, SSDEEP, TLSH, queue operations
- Fuzz harness skeleton

### Post-Port Fixes (2026-04-16)

**Syntax & Semantics**
- Fixed all struct initialization: `StructName {}` → `alloc(N)` + `store64()` (38 structs, 48 init sites)
- Fixed all struct field access: `.field` → `load64(ptr + offset)` (hundreds of sites)
- Fixed `!variable` bitwise NOT → `variable == 0` (6 sites — memmem, strings, ssdeep, elf, yara, script)
- Fixed `|` → `||` and `&` → `&&` in boolean contexts (26 operator fixes)
- Fixed `load64(...) = val` → `store64(..., val)` (12 lvalue assignment sites)
- Fixed `match` reserved keyword collision → renamed to `found`/`hit`
- Fixed `return;` → `return 0;` (13 bare returns)
- Fixed ternary `? :` → if/else

**Stdlib API Alignment**
- `args_count()` → `argc()`, `args_get(n)` → `argv(n)`
- `chrono_now()` → `clock_epoch_secs()`, `chrono_format()` → epoch display
- `json_stringify()` → `json_build()`
- `f64_from_int()` → `f64_from()`, `f64_to_int()` → `f64_to()`
- `sigil_sha256()` → `sha256_hex()`
- `fmt_int()` → `str_from_int()` (24 sites)
- `file_read_all(path)` → 3-arg API with `phylax_read_file()` wrapper
- TOML parser rewritten for flat section-based `toml_parse()` API
- Added `str_lower()`, `str_from_raw()`, `str_to_int()`, `print_int()`, `http_post()` shims

**C-string vs Str Type Fixes**
- `println(str_...)` → `str_println(str_...)` (73 sites)
- `str_eq(argv(...), str_from("..."))` → `streq(argv(...), "...") == 1` (26 CLI sites)
- `strlen()` for C-string length vs `str_len()` for Str (arg parsing)
- `VERSION` and `AGENT_NAME` lazily initialized after `alloc_init()`

**Float Constant Corrections**
- Fixed bit patterns for F64_256, F64_512, F64_4096, F64_7_5, F64_7_0, F64_0_9, F64_15

**Runtime Fixes**
- Heap allocation limit: 50MB → 1MB (fits Cyrius 21MB heap)
- Null check on `phylax_read_file` return before `str_len()`
- Report renderer: integer fields wrapped in `str_from_int()` for `str_cat()`

## [0.5.0] - 2026-03-27

Major feature release: native YARA syntax, deep binary analysis, script obfuscation detection, CI/CD integration, and performance overhaul.

### YARA Rule Engine
- **Native `.yar` syntax parser** — `load_rules_yar()` parses standard YARA rule files
  - Rule declarations with tags: `rule Name : tag1 tag2 { ... }`
  - Meta sections mapped to severity/description
  - String definitions: text literals, hex patterns, regex, with `nocase`, `wide`, `ascii` modifiers
  - Full boolean condition expressions: `and`, `or`, `not`, parentheses
  - `any of them`, `all of them`, `N of them`, `any of ($a, $b)`, `filesize` comparisons
  - `import` statements silently skipped (module system not yet supported)
- **Hex wildcard bytes** (`??`) and **jumps** (`[n-m]`) in hex patterns — auto-compiled to regex
- **Aho-Corasick multi-pattern automaton** — single-pass scanning with adaptive threshold (AC for 8+ patterns, memmem fallback below)
- **`#count` operator** — `#a >= 3` counts pattern occurrences
- **`@offset` operator** — `@a[0] == 0` accesses match positions, with optional index `@a[N]`
- **`for..of` positional constraints** — `for any of ($a, $b) : ($ at 0)`, `for 2 of them : ($ in (0..100))`
- `ConditionExpr` recursive AST with `PatternMatchInfo` carrying counts + offsets
- `RegexBuilder` with 10 MB size/DFA limits to prevent DoS from crafted patterns
- `phylax rules validate` — syntax-check TOML and .yar files without scanning

### Binary Analysis
- **Per-section entropy** — `pe_section_entropy()` / `elf_section_entropy()` with per-section-type thresholds (code > 7.0, data > 7.5)
- **Chi-squared randomness test** — `chi_squared()` + `classify_randomness()` distinguishes encrypted vs compressed vs normal data
- **PE overlay detection** — `detect_pe_overlay()` finds data appended after last section
- **Packed binary heuristics** — `detect_pe_packing()` combines 6 signals: packer section names, W^X sections, hollow sections, few imports, entry in high-entropy section, encrypted overlay
- **PE imphash** — function-level import parsing (ILT/INT with ordinal support) + `compute_imphash()` (SHA-256 variant)
- **PE TLS callback detection** — `has_tls_callbacks` field flags pre-entrypoint execution
- **PE debug directory / PDB path** — `pdb_path` field extracts developer build path
- **PE Rich header parsing** — `rich_entries` with XOR-decrypted toolchain IDs + `rich_product_name()` lookup (VS6 through VS2022+)
- **ELF program header parsing** — segments, interpreter path, security feature detection (RELRO, RWX, static linking, executable stack)

### Script Analysis (NEW)
- **Script language classification** — PowerShell, VBScript, JavaScript, Python, Batch, Shell (shebang + content-based)
- **Obfuscation detection** — per-line entropy analysis, base64 block detection, language-specific patterns:
  - PowerShell: `[char]` chains, `Invoke-Expression`/IEX, `-EncodedCommand`, `-WindowStyle Hidden`
  - VBScript: `Chr()` concatenation, `Execute`/`ExecuteGlobal`, `WScript.Shell`
  - JavaScript: `eval()`, `fromCharCode` chains, `document.write`+`unescape`, hex escape floods

### CI/CD Integration (NEW)
- **SARIF v2.1.0 output** — `--format sarif` for GitHub/GitLab Code Scanning integration
- **Exit codes for pipeline gating** — `--exit-code N` + `--severity-threshold` on `phylax scan`
- **Scan session UUID** — `session_id` on `ScanResult` and `ThreatReport` for audit trails and SIEM correlation
- **JSON structured logging** — `--log-format json` for SIEM ingestion (Splunk, Elastic)

### Finding Management (NEW)
- **Finding fingerprints** — `ThreatFinding::fingerprint()` for stable deduplication across scans
- **Baseline suppression** — `Baseline` struct loads from `.phylax-ignore` or previous scan JSON, filters known findings

### CLI / UX
- **Verbosity flags** — `-v` (info), `-vv` (debug), `-vvv` (trace), `-q` (quiet/error-only)
- rayon parallel file scanning — multi-file `phylax scan` uses `par_iter`
- Eliminated double file read in single-file scan

### Performance
- **`memchr::memmem`** for YARA literal/hex pattern matching — 100-200x faster than naive `windows().any()`
- **`#[inline]`** on 14 hot-path functions — 20-50% improvement on report rendering, findings generation

### Security Hardening
- `HooshClient::new()` / `DaimonClient::new()` return `Result` — no more `.expect()` panics in library code
- PE section count capped to 96 (spec max), ELF section count capped to 1024
- Symlink skip in `collect_files` — prevents directory traversal and infinite loops
- **Quarantine hardening** — canonicalized root, 0700 permissions (Unix), UUID-only filenames, path traversal rejection on release IDs
- `#[non_exhaustive]` on `WatchEvent` enum
- Zero `.unwrap()` / `.expect()` in library code — lexer uses `consume_while` helper

### Correctness
- `escalate_severity` metadata keys now distinct (`escalated_polyglot`, `escalated_executable`, `escalated_signals`)
- `render_json` logs serialization errors instead of silently returning `{}`
- `#[must_use]` on all pure public functions
- `bench-history.sh` fixed to filter criterion `change:` lines

### Dependencies
- Added `memchr = "2"`, `aho-corasick = "1"` (already transitive via regex)
- Added `rayon = "1"`
- Enabled `tracing-subscriber` `json` feature
- Updated `cc` 1.2.58, `mio` 1.2.0, `proptest` 1.11.0, `uuid` 1.23.0

### Quality
- 355 tests (345 unit + 10 integration)
- 13 proptest property-based tests
- 16 benchmark groups with throughput measurement
- 3 fuzz targets (YARA, analyze, entropy)

## [0.22.3] - 2026-03-22

Initial release of the Phylax threat detection engine.

### Core Engine
- Core types: ScanTarget, FindingSeverity, FindingCategory, ThreatFinding, ScanResult, ScanConfig, PhylaxError
- `#[non_exhaustive]` on all public enums
- `#[must_use]` on all pure functions and accessors

### YARA Rule Engine
- Literal, hex, and regex pattern matching with compiled regex caching
- TOML rule loading with All/Any/AtLeast conditions
- `RuleConstraints`: `min_file_size`, `max_file_size`, `at_offset`
- Rules loaded once and reused across multi-file scans

### Binary Analysis
- Shannon entropy with block profiling and suspicious threshold (>7.5 bits/byte)
- Magic bytes detection: ELF, PE, Mach-O, PDF, ZIP, GZIP, PNG, JPEG, Script
- Polyglot file detection
- SHA-256 hashing
- PE header parsing: DOS/COFF/optional headers, sections, imports, exports
- ELF parsing: 32/64-bit, sections, `.dynsym` symbols, `DT_NEEDED` libraries
- ASCII + UTF-16 LE string extraction
- `escalate_severity()`: auto-escalation based on combined signals
- `findings_from_analysis()`: pre-computed analysis to avoid redundant computation

### CLI
- `phylax scan` — single file, multiple files, or recursive directory scanning
- `phylax watch` — filesystem monitoring with auto-scan (inotify/kqueue/FSEvents)
- `phylax daemon` — Unix socket listener with per-connection async handling
- `phylax report` — JSON and Markdown threat reports
- `phylax rules list` — list loaded YARA rules
- `phylax status` — engine status

### Integrations
- Hoosh LLM triage: `--triage` flag sends findings to hoosh `/v1/chat/completions`
- Daimon agent lifecycle: `--register` flag with heartbeat loop and graceful deregistration
- Bote MCP tool registration: 5 tools (feature-gated `bote`)

### Infrastructure
- Priority scan queue (bounded, thread-safe, AtomicU64 IDs)
- Quarantine directory management with persistent JSON index
- Watch mode: extension filtering, file size limits, debounce, periodic cleanup
- Daemon: path canonicalization, 4 KB line limit, hoosh triage integration
- `PHYLAX_LOG` env var for structured logging

### Security
- Zero `unsafe` code
- Daemon path canonicalization prevents traversal
- Daimon/hoosh agent_id validation rejects path separators
- PE RVA arithmetic uses `checked_add`
- Hoosh client 30s request timeout
- Regex crate guarantees linear-time pattern matching

### Quality
- 231 tests (221 unit + 10 integration; 235 with bote feature)
- 13 proptest property-based tests for PE, ELF, and string extraction parsers
- 16 benchmark groups with throughput measurement
- 3 fuzz targets (YARA, analyze, entropy)
- `scripts/bench-history.sh` — CSV + 3-run Markdown tracking
- GitHub Actions CI (9 jobs) + release workflow
- `cargo deny` + `cargo vet` supply chain verification
- Documentation: architecture, threat model, testing guide, dependency watch, SECURITY, CONTRIBUTING
