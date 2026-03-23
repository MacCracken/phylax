# Threat Model

## Trust Boundaries

| Boundary | Trust Level |
|----------|-------------|
| Scanned files | Untrusted — arbitrary binary content |
| YARA rule files | Semi-trusted — authored by analysts |
| CLI arguments | Semi-trusted — local user input |
| Unix socket clients | Semi-trusted — local processes |
| Daimon HTTP API | Trusted — localhost only |
| Hoosh HTTP API | Trusted — localhost only |

## Attack Surface

### core
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Malicious ScanTarget paths | Path traversal | Canonical path resolution |
| Oversized files | Memory exhaustion | `max_file_size` limit (50 MB default) |

### yara
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Malicious regex in rules | ReDoS | `regex` crate (linear-time, no backtracking) |
| Invalid hex patterns | Parse errors | Strict hex validation with error types |
| Oversized rule files | Memory exhaustion | TOML parser limits |

### analyze
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Truncated files | Buffer overread | Bounds-checked slice access |
| Crafted polyglot files | False negatives | Multiple detection passes |
| Empty input | Division by zero | Returns 0.0 for empty data |

### pe / elf
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Crafted headers | Integer overflow in RVA | `checked_add` on all arithmetic |
| Malformed section tables | Out-of-bounds read | Bounds-checked `data.get()` |
| Recursive structures | Stack overflow | Iteration limits (256 imports, 1024 exports, 4096 symbols) |

### strings
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Large files | Memory from extracted strings | `max_file_size` pre-check |

### hoosh
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Hoosh unavailable | Infinite hang | 30s request timeout |
| Malicious LLM response | Classification injection | JSON parsing with fallback, confidence bounds |

### daimon
| Vector | Risk | Mitigation |
|--------|------|-----------|
| SSRF via base_url | Network access | Localhost-only default |
| Path traversal in agent_id | URL injection | Rejects `/` and `\` in agent_id |

### watch
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Symlink loops | Infinite recursion | `notify` crate handles OS-level |
| Event flood | Memory exhaustion | Debounce + periodic HashMap cleanup |

### quarantine
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Index corruption | Lost quarantine metadata | JSON serialize errors logged, not silent |
| Cross-filesystem move | `fs::rename` failure | Same-filesystem assumption documented |

### daemon (Unix socket)
| Vector | Risk | Mitigation |
|--------|------|-----------|
| Path traversal from client | Scanning arbitrary files | `canonicalize()` on all paths |
| Oversized requests | Memory exhaustion | 4 KB line length limit |

## Unsafe Code

Phylax contains **zero** `unsafe` blocks.

## Supply Chain

- `cargo audit` — checks for known vulnerabilities in dependencies
- `cargo deny` — enforces license allowlist, bans wildcards, denies unknown sources
- `cargo vet` — supply chain verification via audits
