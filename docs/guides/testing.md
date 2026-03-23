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
| Unit tests | `src/*.rs` | 208 | `cargo test` |
| Integration tests | `tests/integration.rs` | 4 | `cargo test --test integration` |
| Bote feature tests | `src/bote_tools.rs` | 4 | `cargo test --features bote` |
| Doc tests | Inline in source | 0 | `cargo test --doc` |
| Fuzz tests | `fuzz/fuzz_targets/` | 3 | `cargo +nightly fuzz run <target>` |
| Benchmarks | `benches/benchmarks.rs` | 16 groups | `cargo bench` |

**Total: 212 tests** (208 unit + 4 integration; 216 with bote feature)

## Test Distribution by Module

| Module | Tests | Coverage |
|--------|-------|----------|
| core | 22 | Types, serialization, Display, FromStr, ordering |
| error | 9 | Every PhylaxError variant, #[from] conversion |
| yara | 28 | Patterns, conditions, constraints, TOML loading, edge cases |
| analyze | 32 | Entropy, magic bytes, SHA-256, polyglot, escalation |
| pe | 12 | Header parsing, sections, flags, serialization |
| elf | 14 | 32/64-bit, big/little endian, sections, serialization |
| strings | 12 | ASCII, UTF-16, filtering, sorting |
| hoosh | 13 | Client config, prompt building, response parsing |
| daimon | 7 | URL validation, path traversal rejection |
| ai | 2 | Registration defaults, serialization |
| queue | 9 | Priority ordering, FIFO, capacity, target preservation |
| quarantine | 9 | Quarantine/release, persistence, SHA-256, errors |
| report | 8 | JSON/Markdown rendering, summary, serialization |
| watch | 8 | File detection, extension filter, size filter, config |

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
