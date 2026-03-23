# Threat Model

## Trust Boundaries

| Boundary | Trust Level |
|----------|-------------|
| Scanned files | Untrusted — arbitrary binary content |
| YARA rule files | Semi-trusted — authored by analysts |
| CLI arguments | Semi-trusted — local user input |
| Daimon HTTP API | Trusted — localhost only |
| Hoosh HTTP API | Trusted — localhost only |

## Attack Surface

### core (types and config)
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Malicious ScanTarget paths | Path traversal | Canonical path resolution |
| Oversized files | Memory exhaustion | `max_file_size` limit (50 MB default) |

### yara (rule engine)
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Malicious regex in rules | ReDoS | `regex` crate (linear-time, no backtracking) |
| Invalid hex patterns | Parse errors | Strict hex validation with error types |
| Oversized rule files | Memory exhaustion | Rule count bounded by TOML parser limits |

### analyze (binary analysis)
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Truncated files | Buffer overread | Bounds-checked slice access |
| Crafted polyglot files | False negatives | Multiple detection passes, conservative flagging |
| Entropy calculation on empty input | Division by zero | Handled (returns 0.0 for empty input) |

### daimon (HTTP client)
| Vector | Risk | Mitigation |
|--------|------|-----------|
| SSRF via daimon base_url | Network access | Localhost-only default, URL validation |
| Man-in-the-middle on HTTP | Data integrity | Intended for local-only deployment |

## Unsafe Code

Phylax contains **zero** `unsafe` blocks.

## Supply Chain

- `cargo audit` — checks for known vulnerabilities in dependencies
- `cargo deny` — enforces license allowlist and source restrictions
- `cargo vet` — supply chain verification via audits
