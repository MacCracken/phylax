# Testing Guide

## Running Tests

```bash
# All tests
cyrius test tests/phylax.tcyr

# Build only (syntax check)
cyrius check src/main.cyr

# Run benchmarks
cyrius bench tests/phylax.bcyr

# Track regressions over time
./scripts/bench-history.sh
```

## Test Groups (16)

| Group | What it tests |
|-------|--------------|
| severity | Ordering, ranking, names |
| errors | Error codes, names |
| entropy | Shannon entropy: zeros, two-value, uniform, suspicious threshold |
| chi_squared | Empty, uniform, single-value, classification ranges |
| file_detection | 9 magic byte signatures + unknown + too-short |
| sha256 | Known values, determinism |
| strings | ASCII extraction, printable byte checks |
| pe_parser | Not-PE rejection, too-short, minimal valid header |
| elf_parser | Not-ELF rejection, minimal 64-bit header |
| yara | Engine creation, pattern matching, non-matching |
| queue | Empty, enqueue/dequeue, priority ordering, capacity |
| ssdeep | Empty, single byte, determinism |
| tlsh | Too-short, varied data, determinism, identical distance |
| memmem | Found, not-found, empty needle |
| hex | Encode basic, encode empty |
| report | Empty report, markdown rendering |

## Benchmarks (12 groups)

| Group | What it measures |
|-------|-----------------|
| entropy_1k | Shannon entropy on 1KB |
| entropy_1m | Shannon entropy on 1MB |
| chi_squared | Chi-squared on 4KB |
| file_detection | Magic bytes detection |
| sha256_4k | SHA-256 on 4KB |
| memmem_4k | Byte search in 4KB |
| hex_encode_256 | Hex encoding 256 bytes |
| extract_ascii | String extraction from 4KB |
| ssdeep_4k | SSDEEP hash on 4KB |
| tlsh_1k | TLSH hash on 1KB |
| queue_enqueue | 1000 enqueue operations |
| queue_dequeue | 1000 enqueue + dequeue |

## Fuzzing

```bash
cyrius build tests/phylax.fcyr build/phylax-fuzz
./build/phylax-fuzz
```

## Testing Patterns

- **Edge cases**: empty input, truncated data, oversized files
- **Error paths**: invalid hex, bad patterns, unknown conditions, path traversal
- **Security**: agent_id validation, quarantine path traversal rejection
- **Bounds checking**: every parser tested with too-short data
- **Determinism**: hash functions tested for reproducibility
