# Roadmap

## v0.2.0 — Hardening

- [ ] Integration tests for full scan pipeline
- [ ] Fuzz targets for YARA parsing and binary analysis
- [ ] `cargo deny` + `cargo vet` in CI
- [ ] MSRV policy and testing
- [ ] Coverage target: 80% project, 75% patch
- [ ] Benchmarks for entropy, hashing, YARA scanning throughput

## v0.3.0 — Analysis Depth

- [ ] PE header parsing (sections, imports, exports)
- [ ] ELF section analysis (symbols, dynamic linking)
- [ ] String extraction with encoding detection
- [ ] YARA condition enhancements (file size, offset constraints)
- [ ] Rule severity auto-escalation based on combined signals

## v0.4.0 — Daemon & MCP

- [ ] Full daemon mode with Unix socket listener
- [ ] MCP tool implementation (not just definitions)
- [ ] Scan queue with priority scheduling
- [ ] Quarantine directory management
- [ ] Report generation (JSON, Markdown)

## v1.0.0 — Production

- [ ] API stability guarantee
- [ ] Multi-file and directory scanning
- [ ] Watch mode (inotify/kqueue)
- [ ] Daimon agent lifecycle (register, heartbeat, deregister)
- [ ] Hoosh LLM triage integration
- [ ] Performance targets: >100 MB/s entropy, >50 MB/s full pipeline

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
