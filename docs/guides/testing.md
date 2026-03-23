# Testing Guide

## Running Tests

```bash
# All tests
make test

# Full CI check locally
make check

# With output
cargo test -- --nocapture

# Single module
cargo test yara::tests
cargo test analyze::tests
cargo test watch::tests
```

## Test Categories

| Category | Location | Count | Command |
|----------|----------|-------|---------|
| Unit tests | `src/*.rs` | 221 | `cargo test` |
| Integration tests | `tests/integration.rs` | 10 | `cargo test --test integration` |
| Property tests | `src/{pe,elf,strings}.rs` | 13 | `cargo test proptest` |
| Bote feature tests | `src/bote_tools.rs` | 4 | `cargo test --features bote` |
| Fuzz tests | `fuzz/fuzz_targets/` | 3 | `cargo +nightly fuzz run <target>` |
| Benchmarks | `benches/benchmarks.rs` | 16 groups | `cargo bench` |

**Total: 231 tests** (221 unit + 10 integration; 235 with bote feature)

## Test Distribution by Module

| Module | Tests | Coverage |
|--------|-------|----------|
| analyze | 37 | Entropy, magic bytes, SHA-256, polyglot, escalation, findings |
| yara | 35 | Patterns, conditions, constraints, TOML loading, edge cases |
| core | 23 | Types, serialization, Display, FromStr, ordering |
| pe | 20 | Header parsing, sections, flags, truncation, serialization, **5 proptest** |
| elf | 20 | 32/64-bit, big/little endian, sections, strtab, serialization, **5 proptest** |
| hoosh | 16 | Client config, prompt building, response parsing, batch |
| strings | 15 | ASCII, UTF-16, filtering, sorting, edge cases, **3 proptest** |
| queue | 10 | Priority ordering, FIFO, capacity, target preservation, IDs |
| watch | 9 | File detection, extension filter, size filter, config |
| report | 9 | JSON/Markdown rendering, summary, serialization, escaping |
| quarantine | 9 | Quarantine/release, persistence, SHA-256, errors |
| error | 9 | Every PhylaxError variant, #[from] conversion |
| daimon | 7 | URL validation, path traversal, deregister rejection |
| ai | 2 | Registration defaults, serialization |

## Coverage

```bash
make coverage
open coverage/html/index.html
```

Targets: 80% project, 75% patch (configured in `codecov.yml`).

## Fuzzing

```bash
cargo install cargo-fuzz

# YARA rule parsing with random input
cargo +nightly fuzz run fuzz_yara -- -max_total_time=30

# Binary analysis with random data
cargo +nightly fuzz run fuzz_analyze -- -max_total_time=30

# Entropy calculation edge cases
cargo +nightly fuzz run fuzz_entropy -- -max_total_time=30
```

## Benchmarks

```bash
# All 16 groups
make bench

# Specific group
cargo bench -- entropy
cargo bench -- yara
cargo bench -- full_scan
cargo bench -- strings
cargo bench -- pe_parse

# Track regressions over time
make bench-history
```

### Benchmark Groups (16)

| Group | What it measures |
|-------|-----------------|
| entropy | Shannon entropy at 1KB–1MB |
| entropy_profile | Block profiling at various block sizes |
| entropy_quality | High vs low entropy data |
| file_detection | Magic bytes + polyglot detection |
| sha256 | Hashing throughput at 1KB–1MB |
| analyze | Full binary analysis pipeline |
| yara | Rule loading + scan throughput |
| full_scan | Complete scan pipeline throughput |
| polyglot | Polyglot detection at scale |
| pattern_match | Literal vs hex vs regex pattern speed |
| findings | analyze_findings vs precomputed |
| strings | ASCII + UTF-16 extraction throughput |
| pe_parse | PE header parsing speed |
| elf_parse | ELF header parsing speed |
| queue | Enqueue/dequeue throughput |
| report | JSON + Markdown rendering speed |

## Testing Patterns

- **Serialization roundtrips**: serialize → deserialize → assert equal
- **Edge cases**: empty input, truncated data, oversized files
- **Error paths**: invalid hex, bad regex, unknown conditions, path traversal
- **Security**: agent_id validation, daemon path canonicalization
- **Property-based (proptest)**: parsers never panic on random input, invariants hold across random data
