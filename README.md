# Phylax

**AI-native threat detection engine for AGNOS.**

Phylax (Greek: guardian/watchman) provides real-time threat detection through YARA rule matching, entropy analysis, magic bytes detection, polyglot file identification, and LLM-assisted triage via hoosh.

## Architecture

```
src/
├── main.rs          CLI entry point (scan, daemon, rules, status)
├── lib.rs           Public API root
├── error.rs         PhylaxError enum
├── core.rs          ScanTarget, FindingSeverity, ThreatFinding, ScanResult, ScanConfig
├── yara.rs          YARA rule engine — literal, hex, regex patterns; TOML loading
├── analyze.rs       Entropy, magic bytes, SHA-256, polyglot detection
├── ai.rs            Agent registration, hoosh LLM triage types
└── daimon.rs        Daimon orchestrator HTTP client
```

MCP tool registration is handled externally by [bote](https://github.com/MacCracken/bote).

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

# Enable debug logging
PHYLAX_LOG=debug phylax scan /path/to/file
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

## Building

```bash
make check    # fmt + clippy + test + audit
make build    # release build
make bench    # run benchmarks
make coverage # generate HTML coverage report
```

## License

GPL-3.0
