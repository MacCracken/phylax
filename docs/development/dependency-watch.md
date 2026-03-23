# Dependency Watch

Status tracking for all direct dependencies.

## Runtime Dependencies

| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| `serde` | 1 | Serialization | Derive feature; used everywhere |
| `serde_json` | 1 | JSON serialization | Reports, hoosh API, daemon protocol |
| `toml` | 0.8 | TOML parsing | YARA rule loading |
| `anyhow` | 1 | Error handling | CLI and daemon error chains |
| `thiserror` | 2 | Error derive | PhylaxError, YaraError |
| `tracing` | 0.1 | Structured logging | All library modules |
| `tracing-subscriber` | 0.3 | Log output | CLI with env-filter |
| `tokio` | 1 | Async runtime | Daemon, hoosh client, daimon lifecycle |
| `reqwest` | 0.12 | HTTP client | Hoosh triage, daimon registration |
| `clap` | 4 | CLI parsing | Derive-based argument parsing |
| `chrono` | 0.4 | Date/time | ThreatFinding timestamps, quarantine |
| `uuid` | 1 | Unique IDs | Finding IDs, quarantine IDs |
| `regex` | 1 | Pattern matching | YARA regex patterns (linear-time) |
| `sha2` | 0.10 | Hashing | File SHA-256 |
| `notify` | 8 | Filesystem events | Watch mode (inotify/kqueue/FSEvents) |

## Optional Dependencies

| Crate | Version | Feature | Purpose |
|-------|---------|---------|---------|
| `bote` | 0.22 | `bote` | MCP tool registration |

## Dev Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `criterion` | 0.5 | Benchmarking (16 groups) |
| `tempfile` | 3 | Temporary dirs for quarantine/watch tests |

## MSRV

- **Minimum Supported Rust Version**: 1.85
- Tested in CI via dedicated MSRV job
- `rust-version` field in Cargo.toml

## Upgrade Notes

- `notify` 8.x uses inotify on Linux, kqueue on macOS/BSD, FSEvents not used (ReadDirectoryChanges on Windows)
- `reqwest` 0.12 requires `tokio` 1.x runtime
- `bote` 0.22 must match the AGNOS ecosystem version
