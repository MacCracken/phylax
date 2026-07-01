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

### Dep hygiene — drop transitive agnosys (agnosys → agnodrm decomposition)
- phylax has **no own** `[deps.agnosys]`; its agnosys was purely transitive
  through sigil (the `lib/agnosys.cyr` slice-subscript note at `cyrius.cyml:86`).
- sigil **3.8.1** internalized its trust/firmware modules and dropped
  `[deps.agnosys]` entirely. Bump `[deps.sigil]` **3.8.0 → 3.8.1** to pick up the
  agnosys-free sigil; this removes phylax's last transitive agnosys edge. No
  phylax source change — pin bump + re-vendor only.

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
