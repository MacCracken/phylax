# Benchmarks

Latest: **0.5.0** — 16 benchmark groups, 344 tests (13 proptest), 3 fuzz targets

## entropy

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `shannon/1024` | 1.72 µs | 568 MiB/s |
| `shannon/4096` | 2.62 µs | 1.49 GiB/s |
| `shannon/65536` | 21.5 µs | 2.91 GiB/s |
| `shannon/1048576` | 320 µs | 3.12 GiB/s |

## entropy_profile

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `block/256` (1 MB) | 5.97 ms | ~167 MiB/s |
| `block/1024` (1 MB) | 1.94 ms | ~514 MiB/s |
| `block/4096` (1 MB) | 679 µs | ~1.47 GiB/s |

## sha256

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `hash/1024` | 1.10 µs | ~888 MiB/s |
| `hash/65536` | 37 µs | ~1.69 GiB/s |
| `hash/1048576` | 565 µs | ~1.77 GiB/s |

## yara (memchr::memmem + Aho-Corasick)

| Benchmark | Time | Notes |
|-----------|------|-------|
| `load_rules` (5 rules) | 55 µs | TOML parse + regex compile |
| `scan_random/1024` | 401 ns | memmem (< 8 patterns) |
| `scan_random/65536` | 7.6 µs | ~8.2 GiB/s |
| `scan_random/1048576` | 110 µs | ~9.1 GiB/s |
| `scan_with_match` (64 KB) | 6.3 µs | ELF match |

## full_scan

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `pipeline/4096` | 14 µs | ~279 MiB/s |
| `pipeline/65536` | 197 µs | ~317 MiB/s |
| `pipeline/1048576` | 2.5 ms | ~400 MiB/s |

## strings

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `ascii/1024` | 1.67 µs | ~584 MiB/s |
| `ascii/65536` | 255 µs | ~245 MiB/s |
| `ascii/1048576` | 4.18 ms | ~239 MiB/s |
| `utf16le/65536` | 108 µs | ~579 MiB/s |
| `utf16le/1048576` | 1.95 ms | ~513 MiB/s |

## pattern_match (64 KB, memchr::memmem)

| Benchmark | Time | Notes |
|-----------|------|-------|
| `literal_2byte` | 210 ns | memmem SIMD |
| `literal_31byte` | 1.39 µs | memmem SIMD |
| `hex_4byte` | 1.08 µs | memmem SIMD |
| `regex_simple` | 1.06 µs | Compiled, cached |
| `regex_alternation` | 437 ns | Multi-pattern |

## pe_parse / elf_parse

| Benchmark | Time |
|-----------|------|
| `minimal_pe` | 43 ns |
| `reject_non_pe` | 7.5 ns |
| `minimal_elf` | 13 ns |
| `reject_non_elf` | ~8 ns |

## queue

| Benchmark | Time |
|-----------|------|
| `enqueue_dequeue_1000` | 65 µs |
| `mixed_priorities_1000` | 64 µs |

## report

| Benchmark | Time | Notes |
|-----------|------|-------|
| `render_json` (10×5) | 34 µs | 10 results, 5 findings each |
| `render_markdown` (10×5) | 5.0 µs | |

_Run `make bench` to reproduce. Run `make bench-history` for CSV tracking._
