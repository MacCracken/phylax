# ADR 0002 — The untrusted-input contract for the detection surface

- **Status**: Accepted
- **Date**: 2026-08-23
- **Context**: the 1.2.6 P(-1) closeout audit — a hostile-input sweep of every
  public entry point, plus a guard-page fuzz of the structured parsers

## Context

Phylax exists to read bytes it does not trust. Every buffer that reaches
`parse_pe`, `parse_elf`, the archive scanners or the hashing primitives is, by
definition, attacker-influenced. Two failure classes were found by probing that
surface directly rather than by reading it.

### 1. Null inputs killed the process

29 hostile calls were made against the public entry points. **17 segfaulted**,
and every one of them was a null buffer or a null handle — not a malformed
structure. Negative lengths were already handled correctly, and so were garbage
bytes behind valid magic.

The most reachable of these was `tlsh_distance(a, b)`, which dereferenced both
arguments with no test. `tlsh_hash` returns `0` for input below
`TLSH_MIN_DATA_LEN`, so **any consumer that hashes a short file and then
compares the result kills its own process** — no malice required.

### 2. A file-derived offset could go negative and read below the buffer

`read_strtab_entry` validated only the upper bound:

```cyrius
var off = strtab_offset + name_index;
if (off >= data_len) { return str_from(""); }   # upper bound only
var max = 256;
if (off + max > data_len) { max = data_len - off; }
return read_ascii(data, off, max);
```

Both inputs come from ELF header fields, read as u32/u64 into a **signed** i64.
A field larger than `i64::MAX` arrives negative. `off >= data_len` is then
false, the read proceeds, and `max = data_len - off` comes out *larger than the
whole buffer* — so the parser reads below `data` and keeps going.

This was not theoretical. It was caught as a genuine `SIGSEGV` by placing the
input so its last byte abutted a `PROT_NONE` page, which turns any over-read
into an immediate fault instead of a silent read of neighbouring heap. Two of
5,600 (input × parser) combinations tripped it; both were mutated ELFs whose
`e_shoff` pointed far past end-of-file.

The same upper-bound-only idiom appeared at ~20 further sites across
`pe.cyr` and `elf.cyr`.

## Decision

**1. A public entry point returns its own "nothing here" sentinel for bad
input. It never dereferences and never crashes.**

Each function keeps the sentinel it already used for the empty case, so no
caller has to learn a new convention:

| Function | Bad-input result |
|---|---|
| `shannon_entropy`, `chi_squared` | `F64_ZERO` |
| `detect_file_type` | `FILETYPE_UNKNOWN` |
| `extract_ascii` | empty vec |
| `phylax_hex_encode` | empty `Str` |
| `memmem` | `-1` |
| `ssdeep_hash`, `tlsh_hash` | `0` |
| `ssdeep_compare`, `tlsh_distance` | `-1` |
| `parse_pe`, `parse_elf` | `0` |
| `zip_scan_entries`, `tar_scan_entries`, `gzip_scan` | empty vec |

**2. Every bounds test on a file-derived offset goes through `in_bounds`.**

```cyrius
fn in_bounds(off, need, data_len) {
    if (off < 0) { return 0; }
    if (need < 0) { return 0; }
    if (data_len < 0) { return 0; }
    if (off > data_len) { return 0; }
    if (need > data_len - off) { return 0; }
    return 1;
}
```

`need > data_len - off` is deliberate in place of `off + need > data_len`: once
`off` is known to sit in `[0, data_len]` the subtraction cannot overflow, while
the addition can wrap for a large `need`.

**3. Phylax does not define bare names that a dependency also defines.**

`hex_encode`, `str_to_int` and `str_contains` were phylax-local functions
shadowing stdlib/sigil symbols under last-definition-wins. `hex_encode` was the
dangerous one — phylax's returned a `Str` while sigil's returns a **cstr**, and
sigil's own `sha256_hex`/`sha512_hex` call it — so a consumer linking
`dist/phylax.cyr` alongside sigil got ADR 0001's exact representation bug
injected into sigil's internals. All three are now `phylax_`-prefixed, matching
the existing `phylax_hex_decode` and the `PHYLAX_ERR_*` precedent from 1.2.4.

## Consequences

- **Breaking for `dist/phylax.cyr` consumers** that called `hex_encode`,
  `str_to_int` or `str_contains` — see the 1.2.6 CHANGELOG for the migration.
  Note `str_to_int` and `str_contains` also differed *semantically* from the
  stdlib functions they shadowed (phylax's `str_to_int` stops at the first
  non-digit where stdlib's skips them; phylax's `str_contains` reports an empty
  needle as absent where stdlib's reports it as present), so a caller that was
  silently getting phylax's behaviour keeps it only by taking the new name.

- **`shannon_entropy` pays a measured ~1.95 us per call** for its null test:
  12.95 us → 14.9 us on the 1 KiB benchmark, A/B'd over three runs each. That
  is not real work — it is a code-layout artifact. The function allocates a
  2 KiB frequency table that already sits at the per-function stack budget, and
  one more test in that frame changes how the frame is placed. Hoisting the
  guard into a thin wrapper was tried and did **not** recover it; neither did
  reordering the tests nor merging them into a single `||`.

  Kept regardless. The cost is fixed per call, so it disappears on real
  workloads — `entropy_1m` (a 1 MiB buffer) moves +0.7%, inside noise — and a
  scanner that dies on a null buffer is worse than a scanner that is 15% slower
  on a microbenchmark. Revisit if the toolchain's frame placement improves.

- The guard-page harness and the corpora are throwaway (they live in the
  session scratchpad, not the repo), but the *cases* they found are permanent:
  `tests/test_hardening.tcyr` carries 57 assertions covering `in_bounds`, every
  null entry point, negative lengths, truncated headers and archive depth
  limits.

## Verification

- 29/29 hostile-input entry-point cases return their sentinel (was 17 crashing)
- 0 over-reads across **6,306** guard-page (input × parser) combinations, using
  1,196 mutated PE/ELF/ZIP/TAR/gzip inputs — including 466 structurally-valid
  PEs built specifically to reach the import/export/TLS/debug/cert paths
- 0 abnormal exits scanning all 1,196 inputs end-to-end through the CLI
- 404 assertions across 18 test files pass
- phylax-side `duplicate fn` build warnings: 6 → 0
