# Benchmarks

Latest: **0.22.3** — 16 groups, 212 tests

## entropy

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `shannon/1024` | 1.66 µs | 588 MiB/s |
| `shannon/4096` | 2.44 µs | 1.37 GiB/s |
| `shannon/65536` | 19.5 µs | 2.86 GiB/s |
| `shannon/1048576` | 288 µs | 3.15 GiB/s |

## entropy_profile

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `block/256` (1 MB) | — | ~3 GiB/s |
| `block/1024` (1 MB) | — | ~3 GiB/s |
| `block/4096` (1 MB) | — | ~3 GiB/s |

## sha256

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `hash/1024` | 1.02 µs | ~960 MiB/s |
| `hash/65536` | 32.2 µs | ~1.94 GiB/s |
| `hash/1048576` | 505 µs | ~1.98 GiB/s |

## yara

| Benchmark | Time | Notes |
|-----------|------|-------|
| `load_rules` (5 rules) | 49 µs | TOML parse + regex compile |
| `scan_random/1024` | 17 µs | |
| `scan_random/65536` | 920 µs | ~68 MiB/s |
| `scan_random/1048576` | ~15 ms | ~67 MiB/s |
| `scan_with_match` (64 KB) | 720 µs | ELF match |

## full_scan

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `pipeline/4096` | 83 µs | ~47 MiB/s |
| `pipeline/65536` | 1.16 ms | ~54 MiB/s |
| `pipeline/1048576` | 18 ms | ~56 MiB/s |

## strings

| Benchmark | Time | Throughput |
|-----------|------|-----------|
| `ascii/1024` | 1.73 µs | ~565 MiB/s |
| `ascii/65536` | 250 µs | ~250 MiB/s |
| `ascii/1048576` | 4.19 ms | ~239 MiB/s |
| `utf16le/65536` | 100 µs | ~625 MiB/s |
| `utf16le/1048576` | 1.79 ms | ~559 MiB/s |

## pattern_match (64 KB)

| Benchmark | Time | Notes |
|-----------|------|-------|
| `literal_2byte` | — | Window scan |
| `literal_31byte` | — | Window scan |
| `hex_4byte` | 165 µs | |
| `regex_simple` | — | Compiled, cached |
| `regex_alternation` | — | Multi-pattern |

## pe_parse / elf_parse

| Benchmark | Time |
|-----------|------|
| `minimal_pe` | 40 ns |
| `reject_non_pe` | 7 ns |
| `minimal_elf` | 12 ns |
| `reject_non_elf` | ~4 ns |

## queue

| Benchmark | Time |
|-----------|------|
| `enqueue_dequeue_1000` | 65 µs |
| `mixed_priorities_1000` | 63 µs |

## report

| Benchmark | Time | Notes |
|-----------|------|-------|
| `render_json` (10×5) | 35 µs | 10 results, 5 findings each |
| `render_markdown` (10×5) | 3.7 µs | |

_Run `make bench` to reproduce. Run `make bench-history` for CSV tracking._
