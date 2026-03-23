# Changelog

All notable changes to Phylax will be documented in this file.

## [0.1.0] - 2026-03-22

### Added
- Initial release of the Phylax threat detection engine
- `phylax-core`: Core types (ScanTarget, FindingSeverity, FindingCategory, ThreatFinding, ScanResult, ScanConfig, PhylaxError)
- `phylax-yara`: YARA-compatible rule engine with literal, hex, and regex pattern matching; TOML rule loading; All/Any/AtLeast conditions
- `phylax-analyze`: Shannon entropy calculation, entropy profiling, magic bytes detection (ELF, PE, Mach-O, PDF, ZIP, GZIP, PNG, JPEG, Script), polyglot file detection, SHA-256 hashing, binary analysis
- `phylax-mcp`: 5 MCP tool definitions (phylax_scan, phylax_rules, phylax_status, phylax_quarantine, phylax_report)
- `phylax-ai`: Daimon agent registration client, hoosh LLM triage request/response types
- CLI with `scan`, `daemon`, `rules list`, and `status` subcommands
