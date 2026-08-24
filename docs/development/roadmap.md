# Roadmap

## Completed

### v0.7.5 — Cyrius Port (2026-04-16)
- Full port from Rust (14,133 lines) to Cyrius
- 86 tests, 804KB binary, all 22 modules ported

### v0.8.0 — Feature Parity (2026-04-16)
- YARA module conditions (pe.*/elf.*)
- Config file (phylax.toml)
- CI pipeline gating (--severity-threshold, --exit-code)
- Timestamp formatting, queue binary heap, file detection u32

### v0.8.1 — mmap I/O (2026-04-16)
- Memory-mapped file access, 100MB limit (was 1MB)

### v0.8.2 — Parallel Scanning (2026-04-16)
- 4-thread worker pool for multi-file scans

### v0.8.3 — Archive Scanning (2026-04-16)
- ZIP stored entry scanning with recursive detection
- GZIP detection (deflate decompression pending)
- Bomb protection (depth 3, 1024 entries, 100MB expand)

### v0.9.0 — Hardening & Daemon (2026-04-16)
- O_NOFOLLOW + fstat scan hardening
- Per-scan allocation limits (200MB)
- Unix domain socket daemon mode
- Directory recursion fix (Str path plumbing)
- Rules fetch from URL
- Progress indicator for multi-file scans

## Backlog

### v0.9.1 — TAR Support
- TAR header parsing (512-byte blocks)
- Scan embedded files in TAR archives

### v0.9.2 — Threat Intel
- STIX/TAXII JSON indicator import
- Convert indicators to YARA rules
- MalwareBazaar SHA-256 hash feed

### v0.9.3 — Deflate Decompression
- GZIP/ZIP deflate decompression for compressed entry scanning
- Inflate algorithm implementation in Cyrius

### ~~Dep hygiene — drop transitive agnosys~~ (RESOLVED)
- Closed by the ordinary pin sweeps: sigil 3.8.1 internalized its trust/firmware
  modules and dropped `[deps.agnosys]`, and phylax has been well past that tag
  for several releases (3.12.9 as of 1.2.5). No transitive agnosys edge remains.

### ~~Fix the JSON and SARIF report renderers (SIGSEGV)~~ (RESOLVED)
- Fixed on main immediately after the 1.2.5 sweep — see the CHANGELOG
  `[Unreleased]` stanza and `docs/adr/0001-string-and-json-representation-boundaries.md`.
- Root cause was two representation mistakes, not one: raw argv C-strings handed
  to functions expecting `Str` fat pointers, and a HashMap handed to `json_build`,
  which wants a flat `Vec` of `{key, value}` pairs. Both classes were also live in
  `quarantine.cyr` and `integration.cyr`.
- The pass found **three more crashes** than the original filing: markdown itself
  segfaulted once a scan produced a finding (the empty-report case was the only
  one the old test covered), `Session`/`Generated` rendered as pointer values, and
  `phylax <unknown-command>` crashed on certain argument lengths.
- Renderers now build a `json_v_*` tagged-value tree, so nesting, numbers and
  booleans are real and strings are escaped at build time. Verified: output parses
  as JSON, and the SARIF is valid 2.1.0 with a boolean `executionSuccessful`.
- Coverage: suite **188 → 342 assertions across 15 → 17 files**; JSON/SARIF output
  is parsed back rather than length-checked.

### Dep pruning — the vestigial majra/libro blocks, and the sigil double-stage
- `[deps.majra]` and `[deps.libro]` are referenced by nothing in phylax's link
  closure (staged, DCE-pruned) and have been flagged for a dedicated pruning
  pass since 1.2.4.
- ⚠ Measured at 1.2.5: **simply deleting the two blocks does not help.** The
  pull survives transitively through bote 3.3.7, phylax loses control of the
  versions, and a *larger* majra bundle is staged (locked files 65 → 79).
- The real cost is upstream: libro 2.8.12 declares sigil as a **git** dep, so
  granular `lib/sigil_*.cyr` leaves stage alongside the folded `lib/sigil.cyr`
  monolith. Both are 3.12.9, so the duplicate `sha256_hex` / `sha512_hex` /
  `hex_decode_into` definitions are inert, but they cost ~350 KB of DCE binary
  (2,207,520 → 2,562,016 B). File upstream against libro: now that sigil is a
  folded stdlib module, its git dep should follow sakshi's and be dropped.

## v1.0 Criteria

- All v0.9.x items complete
- Heap management: mmap_anon for large allocs (eliminates heap exhaustion)
- cc5 register spill fix for exit code propagation
- 95%+ test coverage
- Benchmark parity within 5x for core operations
- Security audit complete
- Stable CLI interface (no breaking changes after 1.0)
- Documentation: architecture, API reference, integration guide

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
- WASM plugin system (reconsider post-v1)
