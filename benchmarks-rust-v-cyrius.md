# Benchmarks — Rust vs Cyrius Port

Comparison of phylax performance between the original Rust implementation (v0.5.0, criterion) and the Cyrius port (v0.7.5).

## Rust Baseline (v0.5.0 — 2026-03-26, commit 8b238cf)

Last 3 criterion runs, best estimate shown.

### Entropy

| Benchmark | Rust (best) |
|-----------|------------|
| entropy/shannon/1024 | 1.71 µs |
| entropy/shannon/4096 | 2.54 µs |
| entropy/shannon/65536 | 20.29 µs |
| entropy/shannon/1048576 | 309.46 µs |
| entropy_profile/block/256 | 5.97 ms |
| entropy_profile/block/1024 | 1.86 ms |
| entropy_profile/block/4096 | 679.13 µs |
| entropy_quality/high_entropy | 20.12 µs |
| entropy_quality/low_entropy | 18.21 µs |

### File Detection

| Benchmark | Rust (best) |
|-----------|------------|
| file_detection/detect_type_elf | 808.10 ps |
| file_detection/detect_type_unknown | 2.40 ns |
| file_detection/detect_polyglot | 4.47 µs |

### SHA-256

| Benchmark | Rust (best) |
|-----------|------------|
| sha256/hash/1024 | 1.08 µs |
| sha256/hash/65536 | 34.67 µs |
| sha256/hash/1048576 | 545.95 µs |

### Analysis Pipeline

| Benchmark | Rust (best) |
|-----------|------------|
| analyze/binary_analysis/1024 | 2.82 µs |
| analyze/analyze_findings/1024 | 4.72 µs |
| analyze/binary_analysis/65536 | 54.34 µs |
| analyze/analyze_findings/65536 | 126.24 µs |
| analyze/binary_analysis/1048576 | 857.39 µs |
| analyze/analyze_findings/1048576 | 1.98 ms |

### YARA

| Benchmark | Rust (best) |
|-----------|------------|
| yara/load_rules | 49.41 µs |
| yara/scan_random/1024 | 18.42 µs |
| yara/scan_random/65536 | 997.62 µs |
| yara/scan_random/1048576 | 15.47 ms |
| yara/scan_with_match | 800.85 µs |

### Full Scan Pipeline

| Benchmark | Rust (best) |
|-----------|------------|
| full_scan/pipeline/4096 | 89.70 µs |
| full_scan/pipeline/65536 | 1.22 ms |
| full_scan/pipeline/1048576 | 18.95 ms |

### Pattern Matching

| Benchmark | Rust (best) |
|-----------|------------|
| pattern_match/literal_2byte | 29.60 µs |
| pattern_match/literal_31byte | 187.80 µs |
| pattern_match/hex_4byte | 189.90 µs |
| pattern_match/regex_simple | 1.08 µs |
| pattern_match/regex_alternation | 417.81 ns |

### Polyglot Detection

| Benchmark | Rust (best) |
|-----------|------------|
| polyglot/detect/1024 | 1.35 µs |
| polyglot/detect/65536 | 71.02 µs |
| polyglot/detect/1048576 | 1.10 ms |

### String Extraction

| Benchmark | Rust (best) |
|-----------|------------|
| strings/ascii/1024 | 1.56 µs |
| strings/utf16le/1024 | 620.21 ns |
| strings/all/1024 | 2.45 µs |
| strings/ascii/65536 | 255.44 µs |
| strings/utf16le/65536 | 107.82 µs |
| strings/all/65536 | 373.73 µs |
| strings/ascii/1048576 | 4.18 ms |
| strings/utf16le/1048576 | 1.95 ms |
| strings/all/1048576 | 6.13 ms |

### Findings

| Benchmark | Rust (best) |
|-----------|------------|
| findings/analyze_findings | 127.05 µs |
| findings/precomputed_findings | 71.86 µs |

### Parsers

| Benchmark | Rust (best) |
|-----------|------------|
| pe_parse/minimal_pe | 42.83 ns |
| pe_parse/reject_non_pe | 7.50 ns |
| elf_parse/minimal_elf | 12.99 ns |
| elf_parse/reject_non_elf | 7.75 ns |

### Queue

| Benchmark | Rust (best) |
|-----------|------------|
| queue/enqueue_dequeue_1000 | 64.63 µs |
| queue/mixed_priorities_1000 | 64.32 µs |

### Report

| Benchmark | Rust (best) |
|-----------|------------|
| report/render_json | 34.13 µs |
| report/render_markdown | 5.04 µs |

---

## Cyrius Port (v0.7.5 — 2026-04-16)

_Benchmarks pending — run `cyrius bench tests/phylax.bcyr` to populate._

| Benchmark | Cyrius | vs Rust |
|-----------|--------|---------|
| entropy_1k | — | — |
| entropy_1m | — | — |
| chi_squared | — | — |
| file_detection | — | — |
| sha256_4k | — | — |
| memmem_4k | — | — |
| hex_encode_256 | — | — |
| extract_ascii | — | — |
| ssdeep_4k | — | — |
| tlsh_1k | — | — |
| queue_enqueue | — | — |
| queue_dequeue | — | — |

---

## Notes

- Rust benchmarks used criterion with 3 runs per group (statistical sampling)
- Cyrius benchmarks use the Cyrius bench framework (iteration timing)
- Rust used `memchr::memmem` (SIMD-optimized) for pattern matching; Cyrius uses manual byte search
- Rust used `sha2` crate (assembly-optimized); Cyrius uses `sigil` (pure Cyrius)
- Rust used `aho-corasick` automaton for multi-pattern YARA; Cyrius uses sequential memmem
- Direct comparison requires same workload sizes — see benchmark group names for alignment
