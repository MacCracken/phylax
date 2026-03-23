# Phylax

**AI-native threat detection engine for AGNOS.**

Phylax (Greek: guardian/watchman) provides real-time threat detection through YARA rule matching, entropy analysis, magic bytes detection, polyglot file identification, and LLM-assisted triage via hoosh.

## Architecture

```
phylax (CLI + daemon)
  |
  +-- phylax-core      Core types: ScanTarget, FindingSeverity, ThreatFinding, ScanResult
  +-- phylax-yara      YARA-compatible rule engine with literal, hex, and regex patterns
  +-- phylax-analyze   Shannon entropy, magic bytes, SHA-256, polyglot detection
  +-- phylax-mcp       MCP tool definitions (5 tools for daimon integration)
  +-- phylax-ai        Daimon agent registration + hoosh LLM triage client
```

## Usage

```bash
# Scan a file
phylax scan /path/to/suspicious.bin

# Scan with custom YARA rules
phylax scan /path/to/file --rules rules.toml

# List loaded rules
phylax rules list --file rules.toml

# Show engine status
phylax status

# Run as daemon (planned)
phylax daemon
```

## YARA Rules Format

Rules are defined in TOML:

```toml
[[rule]]
name = "detect_elf"
description = "Detects ELF binaries"
severity = "medium"
tags = ["elf", "linux"]
condition = "any"

[[rule.patterns]]
id = "$magic"
type = "hex"
value = "7f454c46"

[[rule]]
name = "detect_script"
severity = "low"
condition = "any"

[[rule.patterns]]
id = "$shebang"
type = "regex"
value = "^#!"
```

Pattern types: `literal` (UTF-8 string), `hex` (hex-encoded bytes), `regex` (byte regex).

Conditions: `all`, `any`, `at_least_N`.

## MCP Tools

| Tool | Description |
|------|-------------|
| `phylax_scan` | Scan a target for threats |
| `phylax_rules` | List/search/inspect YARA rules |
| `phylax_status` | Engine status and statistics |
| `phylax_quarantine` | Quarantine or release flagged targets |
| `phylax_report` | Generate threat reports |

## Building

```bash
cargo build --release
cargo test --workspace
```

## License

GPL-3.0
