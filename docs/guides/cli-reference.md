# CLI Reference

## Global Options

```
phylax --version, -V    Print version and exit
phylax --help, -h       Print help text
phylax help             Print help text
```

## Commands

### phylax scan

Scan files or directories for threats using YARA rules, entropy analysis, magic bytes detection, PE/ELF parsing, and archive scanning.

```
phylax scan [OPTIONS] <PATHS...>
```

**Options:**

| Flag | Description |
|------|-------------|
| `--rules <file>` | Load custom YARA rules (.yar or TOML format) |
| `--triage` | Enable LLM-assisted triage via Hoosh |
| `--hoosh-url <url>` | Hoosh endpoint (default: `http://localhost:8080`) |
| `--block-size <n>` | Block size for entropy analysis |
| `--severity-threshold <level>` | Minimum severity to trigger exit code (`info`, `low`, `medium`, `high`, `critical`) |
| `--exit-code <n>` | Exit code when threshold is met (default: 1) |

**Behavior:**

- Single files are scanned directly
- Directories are recursed (hidden files/dirs starting with `.` are skipped)
- Files > 50 MB are skipped with a warning
- If >= 4 files, scanning is parallelized across 4 threads
- Per-scan allocation limit: 200 MB
- Symlinks are rejected (O_NOFOLLOW)

**Scan Pipeline:**

1. Read file (mmap for > 64KB, alloc+read for smaller)
2. Binary analysis: entropy, chi-squared, magic bytes, SHA-256
3. YARA engine: 7 built-in rules + custom rules
4. Severity escalation (entropy+polyglot, executable type, multiple signals)
5. Archive scanning: ZIP stored entries (recursive, depth 3), TAR, GZIP detection
6. Baseline filtering via `.phylax-ignore` (if present)

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no findings at or above threshold |
| 1 (default) | Findings at or above severity threshold |
| N | Custom exit code via `--exit-code` |

**Examples:**

```bash
phylax scan /tmp/suspicious
phylax scan /home/user/downloads --rules custom.yar
phylax scan /opt/uploads --severity-threshold high --exit-code 2
```

### phylax report

Generate a threat report by scanning targets and rendering results.

```
phylax report [OPTIONS] <PATH>
```

**Options:**

| Flag | Description |
|------|-------------|
| `--format <fmt>` | Output format: `json`, `markdown`, `sarif` (default: `markdown`) |
| `--rules <file>` | Load custom YARA rules |

**Output Formats:**

- **markdown** (default): Pipe-escaped table with findings, severity, and metadata
- **json**: Machine-readable JSON with all scan results and metadata
- **sarif**: SARIF v2.1.0 format for integration with code analysis platforms

**Examples:**

```bash
phylax report /var/log --format sarif
phylax report /tmp/malware-sample --format json
phylax report /opt/builds
```

### phylax watch

Watch directories for file changes using inotify and scan on events.

```
phylax watch [OPTIONS] <PATHS...>
```

**Options:**

| Flag | Description |
|------|-------------|
| `--recursive` | Watch directories recursively (one level of subdirectories) |
| `--extensions <exts>` | Comma-separated file extensions to filter (e.g., `exe,dll,so`) |
| `--rules <file>` | Load custom YARA rules |

**Monitored Events:**

- `IN_CREATE` — new file created
- `IN_MODIFY` — file modified
- `IN_CLOSE_WRITE` — file closed after writing
- `IN_MOVED_TO` — file moved into watched directory

**Behavior:**

- Runs indefinitely until Ctrl+C
- Prints `[ALERT]` lines for files with findings
- Uses the full scan pipeline per event

**Examples:**

```bash
phylax watch /opt/uploads --recursive
phylax watch /tmp --extensions exe,dll --rules custom.yar
```

### phylax daemon

Run as a daemon listening on a Unix domain socket for scan requests.

```
phylax daemon [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--socket <path>` | Unix socket path (default: `/tmp/phylax.sock`) |
| `--rules <file>` | Load custom YARA rules |

**Protocol:**

1. Client connects to the Unix domain socket
2. Client sends a file path (max 4095 bytes, newline-terminated)
3. Daemon scans the file using the full pipeline
4. Daemon responds with JSON and closes the connection

**Response Format:**

```json
{"findings":N,"status":"ok"}
```

Where `N` is the number of threat findings.

**Behavior:**

- Single-threaded, one connection at a time
- Existing socket file is removed on startup
- Socket file is cleaned up on shutdown

**Examples:**

```bash
phylax daemon --socket /tmp/phylax.sock
phylax daemon --rules /etc/phylax/rules.yar

# Client usage:
echo "/path/to/file" | socat - UNIX-CONNECT:/tmp/phylax.sock
```

### phylax rules

Manage YARA rules: list, validate, or fetch.

#### phylax rules list

```
phylax rules list [file]
```

List all loaded rules in a table format. If a file is specified, rules from that file are loaded in addition to the 7 built-in rules.

**Output:**

```
Loaded N rule(s)

Name                           | Severity | Tags
-------------------------------|----------|-----
SuspiciousMZ                   | MEDIUM   | pe, executable
```

#### phylax rules validate

```
phylax rules validate <FILES...>
```

Parse and validate YARA rule files. Supports both .yar and TOML formats.

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All files valid |
| 1 | One or more files failed to parse |

#### phylax rules fetch

```
phylax rules fetch <URL> [output_file]
```

Download YARA rules from a URL and save to a local file.

- Default output: `rules.yar`
- Validates downloaded rules after saving
- Supports both .yar and TOML formats

**Examples:**

```bash
phylax rules list
phylax rules list custom.yar
phylax rules validate rules/*.yar
phylax rules fetch https://example.com/rules.yar custom-rules.yar
```

### phylax intel

Import threat intelligence indicators.

#### phylax intel import

```
phylax intel import <STIX_FILE>
```

Import STIX 2.1 JSON threat intelligence. Extracts SHA-256 hash indicators and generates YARA rules.

**Behavior:**

- Scans the STIX JSON for 64-character hex strings (SHA-256 hashes)
- Generates one YARA rule per hash indicator
- Writes output to `phylax-intel.yar`

**Example:**

```bash
phylax intel import stix-bundle.json
# Output: Extracted 42 SHA-256 indicators -> phylax-intel.yar (3,456 bytes)
```

### phylax status

Show engine status and capabilities.

```
phylax status
```

**Output:**

```
Phylax Threat Detection Engine v1.0.0-rc1

Status: active
Timestamp: 2026-04-16 12:00:00

Default rules loaded: 7
Capabilities: 11
  - file_scan
  - binary_analysis
  - yara_matching
  - pe_parsing
  - elf_parsing
  - entropy_analysis
  - string_extraction
  - ssdeep_hashing
  - tlsh_hashing
  - quarantine
  - threat_reporting

Consumers: daimon, aegis, t-ron
```

## Configuration

Phylax loads configuration from TOML files in this order:

1. `./phylax.toml` (current directory)
2. `$HOME/.config/phylax/config.toml`

CLI flags override config file values.

**Example `phylax.toml`:**

```toml
[scan]
rules_path = "/etc/phylax/rules.yar"
max_file_size = 1048576

[hoosh]
url = "http://localhost:8080"

[daimon]
url = "http://localhost:9090"
```

## Built-in Rules

Phylax ships with 7 built-in YARA rules:

| Rule | Severity | Description |
|------|----------|-------------|
| SuspiciousMZ | MEDIUM | Detects MZ (PE) header at file start |
| SuspiciousELF | MEDIUM | Detects ELF header at file start |
| UPXPacked | MEDIUM | Detects UPX-packed binaries (2+ of UPX0/UPX1/UPX! strings) |
| NopSled | HIGH | Detects 32-byte NOP sled (shellcode indicator) |
| SuspiciousAPIs | MEDIUM | Detects suspicious Windows API references (VirtualAllocEx, WriteProcessMemory, etc.) |
| RansomwareIndicators | CRITICAL | Detects ransomware-related strings (encrypt, bitcoin, ransom, etc.) |
| EmbeddedPE | HIGH | Detects embedded PE executable in files > 512 bytes |
