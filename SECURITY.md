# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.22.x  | Yes       |
| < 0.22  | No        |

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
| YARA regex patterns | ReDoS from malicious rule files | `regex` crate with linear-time guarantees |
| File scanning | Path traversal, symlink following | Canonical path resolution, size limits |
| PE/ELF parsing | Integer overflow, out-of-bounds | `checked_add`, bounds-checked `data.get()` |
| String extraction | Memory from large files | `max_file_size` pre-check |
| Entropy analysis | Memory exhaustion on large files | `max_file_size` config (default 50 MB) |
| Magic bytes detection | Buffer overread on truncated files | Bounds-checked slice access |
| Daemon socket | Path traversal from clients | `canonicalize()`, 4 KB line limit |
| Hoosh HTTP client | Timeout, response injection | 30s timeout, JSON parsing with fallback |
| Daimon HTTP client | SSRF, URL injection | Localhost-only default, agent_id validation |
| Quarantine index | Corruption, silent write failure | Warning on save errors, JSON roundtrip |
| Watch mode | Event flood, memory leak | Debounce, periodic HashMap cleanup |

## Security Practices

- Zero `unsafe` code in the entire crate
- CI runs `cargo audit` (dependency vulnerability scanning)
- CI runs `cargo deny` (license and supply chain validation)
- CI runs `cargo vet` (supply chain verification)
- Fuzz targets test YARA parsing and binary analysis with random input
- All file I/O respects `ScanConfig::max_file_size` bounds
- Regex patterns use the `regex` crate (guaranteed linear-time, no backtracking)
- `#[non_exhaustive]` on all public enums for forward compatibility
- No panicking paths in production code

## Threat Model

See [docs/development/threat-model.md](docs/development/threat-model.md) for the full threat model including attack surface analysis per module.
