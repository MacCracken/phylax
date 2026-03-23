# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Phylax:

1. **Do not** open a public GitHub issue
2. Use [GitHub Security Advisories](https://github.com/MacCracken/phylax/security/advisories/new) to report privately
3. Include: description, steps to reproduce, impact assessment
4. **Response SLA**: acknowledgement within 72 hours, fix within 14 days for critical issues
5. We will coordinate disclosure timing with you

## Scope

Phylax is a threat detection engine. Security-relevant areas include:

| Area | Risk | Mitigation |
|------|------|-----------|
| YARA regex patterns | ReDoS from malicious rule files | Regex crate with linear-time guarantees |
| File scanning | Path traversal, symlink following | Canonical path resolution, size limits |
| Entropy analysis | Memory exhaustion on large files | `max_file_size` config (default 50 MB) |
| Magic bytes detection | Buffer overread on truncated files | Bounds-checked slice access |
| MCP tool interface | Injection via untrusted input | Strict schema validation on all tools |
| Daimon HTTP client | SSRF via crafted base URLs | URL validation, localhost-only default |

## Security Practices

- Zero `unsafe` code in the entire workspace
- CI runs `cargo audit` (dependency vulnerability scanning)
- CI runs `cargo deny` (license and supply chain validation)
- Fuzz targets test YARA parsing and binary analysis with random input
- All file I/O respects `ScanConfig::max_file_size` bounds
- Regex patterns use the `regex` crate (guaranteed linear-time, no backtracking)
- No panicking paths in production code

## Threat Model

See [docs/development/threat-model.md](docs/development/threat-model.md) for the full threat model including attack surface analysis and mitigations table.
