# Contributing to Phylax

Thank you for considering contributing to Phylax. This guide will help you get started.

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
| `make fmt-check` | Check formatting |
| `make clippy` | Lint with `-D warnings` |
| `make test` | Run all workspace tests |
| `make audit` | Check dependencies for vulnerabilities |
| `make deny` | Supply chain and license check |
| `make doc` | Build docs with `-D warnings` |
| `make coverage` | Generate HTML coverage report |

## What to contribute

- Bug fixes with regression tests
- New analysis modules (binary format parsers, heuristic detectors)
- YARA rule improvements (new pattern types, condition operators)
- MCP tool enhancements
- Documentation improvements and examples
- Integration tests and fuzz targets

## Code style

- `cargo fmt` — required, checked in CI
- `cargo clippy -- -D warnings` — zero warnings
- Explicit types on public API boundaries
- Doc comments (`///`) on all public types and functions
- Minimal dependencies — prefer pure Rust
- `#[non_exhaustive]` on public enums

## Project layout

```
src/
├── main.rs          # CLI entry point (scan, daemon, rules, status)
├── lib.rs           # Public API root
├── error.rs         # PhylaxError enum
├── core.rs          # ScanTarget, ThreatFinding, ScanResult, ScanConfig
├── yara.rs          # YARA rule engine: literal, hex, regex patterns; TOML loading
├── analyze.rs       # Binary analysis: entropy, magic bytes, SHA-256, polyglot detection
├── ai.rs            # Agent registration, hoosh LLM triage types
└── daimon.rs        # Daimon orchestrator HTTP client
```

MCP tool registration is handled by [bote](https://github.com/MacCracken/bote).

## Adding a new analyzer

1. Add the analysis function in `src/analyze.rs` (or a new module)
2. Return `Vec<ThreatFinding>` for integration with the scan pipeline
3. Add unit tests covering edge cases (empty input, truncated data, known-good files)
4. Wire it into `cmd_scan()` in `src/main.rs`
5. Add a fuzz target if the analyzer processes untrusted input

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
