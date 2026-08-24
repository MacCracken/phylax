# Testing Guide

## Running Tests

```bash
# All tests — one binary per module, so a crash in one doesn't poison the rest
for t in tests/*.tcyr; do cyrius test "$t"; done

# A single module
cyrius test tests/test_report.tcyr

# [lib.core] profile smoke test
cyrius test tests/phylax-core.tcyr

# Run benchmarks
cyrius bench tests/phylax.bcyr
cyrius bench tests/phylax-core.bcyr

# Track regressions over time
./scripts/bench-history.sh
```

Each `tests/test_<module>.tcyr` includes `src/lib.cyr` and defines its own
`main()`. `tests/test_cli.tcyr` additionally includes `src/cli.cyr` — its
`main()` shadows cli.cyr's (last definition wins), which is what makes the
argv-facing subcommand helpers reachable from a test. CLI-boundary tests
belong there.

## Test Groups

| File | Groups | What it tests |
|------|--------|--------------|
| `test_severity.tcyr` | severity, category, errors, parse_severity | Ordering, ranking, names, error codes |
| `test_analyze.tcyr` | entropy, chi_squared, file_detection, tar_detect | Shannon entropy, chi-squared classification, 9 magic-byte signatures, polyglot |
| `test_sha256.tcyr` | sha256 | Known values, determinism |
| `test_strings.tcyr` | strings | ASCII + UTF-16 extraction, printable byte checks |
| `test_pe.tcyr` | pe_parser | Not-PE rejection, too-short, minimal valid header, imports |
| `test_elf.tcyr` | elf_parser | Not-ELF rejection, minimal 64-bit header, security features |
| `test_archive.tcyr` | archive | ZIP / TAR / GZIP entry walking |
| `test_yara.tcyr` | yara | Engine creation, pattern matching, non-matching |
| `test_queue.tcyr` | queue | Empty, enqueue/dequeue, priority ordering, capacity |
| `test_ssdeep.tcyr` | ssdeep | Empty, single byte, determinism |
| `test_tlsh.tcyr` | tlsh | Too-short, varied data, determinism, identical distance |
| `test_utils.tcyr` | memmem, hex | Found / not-found / empty needle; encode basic + empty |
| `test_report.tcyr` | report_summary, report_json_*, report_sarif_*, report_markdown_* | Summary accounting, and each renderer separately — JSON/SARIF output is parsed back with `json_v_parse` and walked field by field, plus metacharacter round-trips, markdown pipe escaping and null-`ScanTarget.data` handling |
| `test_cli.tcyr` | rules_validate, collect_files, run_scan_target, run_scan_rules, path_extension | The argv-cstr → `Str` boundary: `cmd_rules_validate` over valid / unreadable / rule-less / mixed batches, `collect_files`, `run_scan` target typing through all three renderers, `--rules` edge cases, `--extensions` matching |
| `test_quarantine.tcyr` | quarantine_id, quarantine_roundtrip, quarantine_release, quarantine_missing | Id validation + generation, index save→reload round-trip, release-by-id with traversal/unknown-id rejection, missing source |
| `test_integration.tcyr` | fingerprint, baseline, timestamp, config, scan_pipeline | Cross-module paths |
| `phylax-core.tcyr` | core_* | `[lib.core]` compiles standalone and its primitives behave |

Renderer and quarantine coverage is deliberately assertion-heavy: through
1.2.5 `test_report.tcyr` held two assertions and exercised only
`report_render_markdown` on an empty report, which hid SIGSEGVs in both other
renderers and in markdown-with-findings. See the [Unreleased] CHANGELOG entry.

## Benchmarks (15 groups)

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
| report_json_100 | `report_render_json` on a 100-finding report |
| report_sarif_100 | `report_render_sarif` on a 100-finding report |
| report_markdown_100 | `report_render_markdown` on a 100-finding report |

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
