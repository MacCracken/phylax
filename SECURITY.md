# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.7.x   | Yes       |
| < 0.7   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Phylax:

1. **Do not** open a public GitHub issue
2. Use [GitHub Security Advisories](https://github.com/MacCracken/phylax/security/advisories/new) to report privately
3. Include: description, steps to reproduce, impact assessment
4. **Response SLA**: acknowledgement within 48 hours, fix within 14 days for critical issues
5. We will coordinate disclosure timing with you

## Scope

Phylax is a threat detection engine that processes untrusted binary data. Security-relevant areas:

| Area | Risk | Mitigation |
|------|------|-----------|
| YARA regex patterns | ReDoS from malicious rule files | Pattern matching with bounded iteration |
| File scanning | Path traversal, symlink following | Canonical path resolution, size limits |
| PE/ELF parsing | Integer overflow, out-of-bounds | Bounds-checked `load8/16/32/64` with offset validation |
| String extraction | Memory from large files | `max_file_size` pre-check |
| Entropy analysis | Memory exhaustion on large files | `max_file_size` config (default 50 MB) |
| Magic bytes detection | Buffer overread on truncated files | Bounds-checked buffer access |
| Hoosh HTTP client | Timeout, response injection | Synchronous HTTP with JSON parsing fallback |
| Daimon HTTP client | SSRF, URL injection | Localhost-only default, agent_id validation |
| Quarantine index | Corruption, silent write failure | Warning on save errors, JSON roundtrip |
| Watch mode | Event flood, memory leak | Debounce via inotify |

## Security Practices

- No `unsafe` code — Cyrius provides direct memory access with explicit bounds checking
- CI runs `cyrius lint` (static analysis)
- CI runs `cyrius vet` (include verification)
- CI runs `cyrius deny` (policy enforcement)
- Fuzz targets test YARA parsing and binary analysis with random input
- All file I/O respects `max_file_size` bounds
- Pattern matching uses bounded iteration (4096 max match offsets)
- PE section count capped to 96, ELF to 1024, symbols to 4096
- Path traversal rejection on quarantine IDs and agent IDs
- No panicking paths in production code

## Threat Model

See [docs/development/threat-model.md](docs/development/threat-model.md) for the full threat model including attack surface analysis per module.
