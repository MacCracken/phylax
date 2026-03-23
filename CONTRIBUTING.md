# Contributing to Phylax

Thank you for considering contributing to Phylax. This guide will help you get started.

## Prerequisites

- Rust 1.85+ (MSRV)
- Components: `rustfmt`, `clippy`
- Optional: `cargo-audit`, `cargo-deny`, `cargo-fuzz`, `cargo-llvm-cov`

## Getting started

```bash
git clone https://github.com/MacCracken/phylax
cd phylax
make check   # runs fmt-check + clippy + test + audit
```

## Development workflow

| Command | What it does |
|---------|-------------|
| `make check` | Full CI locally (fmt, clippy, test, audit) |
| `make fmt` | Format all code |
| `make clippy` | Lint with `-D warnings` |
| `make test` | Run all tests |
| `make bench` | Run 16 benchmark groups |
| `make bench-history` | CSV + 3-run Markdown tracking |
| `make doc` | Build docs with `-D warnings` |
| `make coverage` | Generate HTML coverage report |
| `make deny` | Supply chain and license check |
| `make vet` | cargo-vet verification |

## What to contribute

- Bug fixes with regression tests
- New analysis modules (binary format parsers, heuristic detectors)
- YARA rule improvements (new pattern types, condition operators)
- Documentation improvements and examples
- Integration tests and fuzz targets
- Benchmark improvements

## Code style

- `cargo fmt` — required, checked in CI
- `cargo clippy -- -D warnings` — zero warnings
- `#[non_exhaustive]` on public enums
- Doc comments (`///`) on all public types and functions
- No `println!` in library modules — use `tracing` instead
- No `unsafe` code
- Minimal dependencies — prefer pure Rust

## Project layout

```
src/
├── main.rs          # CLI (scan, daemon, watch, report, rules, status)
├── lib.rs           # Public API root
├── core.rs          # ScanTarget, ThreatFinding, ScanResult, ScanConfig
├── error.rs         # PhylaxError enum
├── yara.rs          # YARA rule engine — patterns, conditions, constraints
├── analyze.rs       # Entropy, magic bytes, SHA-256, polyglot, escalation
├── pe.rs            # PE header parsing (sections, imports, exports)
├── elf.rs           # ELF parsing (32/64-bit, sections, symbols, DT_NEEDED)
├── strings.rs       # ASCII + UTF-16 LE string extraction
├── hoosh.rs         # HooshClient — LLM triage via hoosh
├── daimon.rs        # DaimonClient — agent lifecycle with daimon
├── ai.rs            # AgentRegistration, capability constants
├── bote_tools.rs    # Bote MCP tool registration (feature-gated)
├── queue.rs         # Priority scan queue
├── quarantine.rs    # File quarantine/release with persistent index
├── report.rs        # ThreatReport generation (JSON, Markdown)
└── watch.rs         # Filesystem watch mode (inotify/kqueue/FSEvents)
```

## Adding a new analyzer

1. Create `src/your_module.rs` with analysis functions
2. Return `Vec<ThreatFinding>` for integration with the scan pipeline
3. Add `pub mod your_module;` in `lib.rs`
4. Add unit tests covering edge cases (empty input, truncated data, known-good files)
5. Wire it into `run_scan_with_engine()` in `src/main.rs`
6. Add a fuzz target if the analyzer processes untrusted input
7. Add benchmarks in `benches/benchmarks.rs`

## Commit messages

- Use imperative mood: "add PE header parser" not "added PE header parser"
- Keep subject under 72 characters
- Reference issues where applicable: "fix #42: handle truncated ELF headers"

## Pull requests

- One logical change per PR
- Include tests for new functionality
- Update docs if the public API changes
- All CI checks must pass (fmt, clippy, test, audit, deny)

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0.
