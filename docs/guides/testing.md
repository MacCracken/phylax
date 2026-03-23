# Testing Guide

## Running Tests

```bash
# All workspace tests
make test

# Full CI check locally
make check

# Single crate
cargo test -p phylax-yara

# With output
cargo test --workspace -- --nocapture
```

## Test Categories

| Category | Location | Command |
|----------|----------|---------|
| Unit tests | `crates/*/src/lib.rs` | `cargo test --workspace` |
| Integration tests | `tests/integration.rs` | `cargo test --test integration` |
| Doc tests | Inline in source | `cargo test --doc` |
| Fuzz tests | `fuzz/fuzz_targets/` | `cargo +nightly fuzz run <target>` |
| Benchmarks | `benches/benchmarks.rs` | `cargo bench` |

## Coverage

```bash
# Generate HTML report
make coverage

# View
open coverage/html/index.html
```

Targets: 80% project, 75% patch (configured in `codecov.yml`).

## Fuzzing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a fuzz target (30 seconds)
cargo +nightly fuzz run fuzz_yara -- -max_total_time=30
cargo +nightly fuzz run fuzz_analyze -- -max_total_time=30
cargo +nightly fuzz run fuzz_entropy -- -max_total_time=30
```

## Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific group
cargo bench -- entropy
cargo bench -- yara
cargo bench -- full_scan

# View HTML reports
open target/criterion/report/index.html
```
