# Integration Guide

## Hoosh LLM Triage

Phylax integrates with [Hoosh](https://github.com/MacCracken/agnosticos) (OpenAI-compatible LLM gateway) for automated threat triage of findings.

### Setup

1. Run a Hoosh instance with an OpenAI-compatible chat completions endpoint
2. Configure the URL in `phylax.toml`:

```toml
[hoosh]
url = "http://localhost:8080"
```

Or pass it at scan time:

```bash
phylax scan /path/to/file --triage --hoosh-url http://localhost:8080
```

### Request Format

Phylax sends a chat completion request to `{base_url}/v1/chat/completions`:

```json
{
  "model": "gpt-4",
  "messages": [
    {"role": "system", "content": "You are a cybersecurity threat triage assistant. Respond with valid JSON only."},
    {"role": "user", "content": "<finding details: rule name, severity, description, metadata>"}
  ],
  "temperature": 0
}
```

### Response Format

Hoosh returns an OpenAI-compatible response. Phylax extracts `choices[0].message.content` and parses it as a triage result with:

- **classification**: `true_positive`, `false_positive`, or `needs_review`
- **confidence**: integer percentage (0-100)
- **explanation**: free-text reasoning

### Output

When `--triage` is enabled, each finding includes a triage line:

```
    HIGH | polyglot_file: Polyglot file detected
    -> triage: true_positive (87%)
```

## Daimon Orchestrator

Phylax registers as a threat-scanning agent with the [Daimon](https://github.com/MacCracken/agnosticos) orchestrator for centralized agent management.

### Registration

```
POST {base_url}/v1/agents/register
```

**Request:**

```json
{
  "name": "phylax",
  "version": "1.0.0-rc1",
  "capabilities": ["file_scan", "yara", "entropy", "pe_parse", "elf_parse", "quarantine"]
}
```

**Response:**

```json
{
  "agent_id": "abc123"
}
```

The returned `agent_id` is validated against path traversal characters before use.

### Heartbeat

```
POST {base_url}/v1/agents/{agent_id}/heartbeat
```

**Request:**

```json
{
  "status": "active",
  "timestamp": 1713273600
}
```

### Deregistration

```
POST {base_url}/v1/agents/{agent_id}/deregister
```

Uses POST with `_method` override as the Cyrius HTTP layer only supports POST/GET.

**Request:**

```json
{
  "agent_id": "abc123"
}
```

### Configuration

```toml
[daimon]
url = "http://localhost:9090"
```

### Agent ID Validation

All agent IDs received from Daimon are validated before use in URL construction:
- Empty IDs are rejected
- Forward slash (`/`) and backslash (`\`) are rejected
- The `..` sequence is rejected

## Bote MCP Tools

Phylax registers 5 tools with the [Bote](https://github.com/MacCracken/agnosticos) MCP (Model Context Protocol) registry for external access by AI agents.

### Tool: phylax_scan

Scan a file for threats.

**Schema:**

```json
{
  "type": "object",
  "properties": {
    "target": {"type": "string", "description": "Path to file to scan"},
    "target_type": {"type": "string", "enum": ["file", "agent", "package", "memory"]},
    "enable_yara": {"type": "boolean"},
    "enable_entropy": {"type": "boolean"}
  },
  "required": ["target", "target_type"]
}
```

**Response:**

```json
{
  "file_type": "PE",
  "sha256": "abc123...",
  "size": 1024,
  "suspicious_entropy": false
}
```

### Tool: phylax_rules

List, search, or inspect loaded YARA rules.

**Schema:**

```json
{
  "type": "object",
  "properties": {
    "action": {"type": "string", "enum": ["list", "search", "inspect"]},
    "query": {"type": "string", "description": "Search query or rule name"}
  },
  "required": ["action"]
}
```

### Tool: phylax_status

Get engine status.

**Schema:**

```json
{
  "type": "object",
  "properties": {
    "verbose": {"type": "boolean", "description": "Include detailed statistics"}
  },
  "required": []
}
```

**Response:**

```json
{
  "status": "ready",
  "version": "1.0.0-rc1",
  "analyzers": ["entropy", "magic_bytes", "yara", "polyglot", "pe", "elf", "strings", "ssdeep", "tlsh", "script"]
}
```

### Tool: phylax_quarantine

Quarantine, release, or list quarantined files.

**Schema:**

```json
{
  "type": "object",
  "properties": {
    "action": {"type": "string", "enum": ["quarantine", "release", "list"]},
    "target": {"type": "string", "description": "Path or quarantine ID"},
    "reason": {"type": "string", "description": "Reason for action"}
  },
  "required": ["action"]
}
```

### Tool: phylax_report

Generate a threat report.

**Schema:**

```json
{
  "type": "object",
  "properties": {
    "target": {"type": "string", "description": "Specific target to report on"},
    "format": {"type": "string", "enum": ["json", "markdown"]}
  },
  "required": []
}
```

### Registration

Tools are registered via `phylax_register_tools(registry, dispatcher)` which calls `registry_register` for each tool definition and `dispatcher_handle` for tools with handlers (phylax_scan and phylax_status have direct handlers; phylax_rules, phylax_quarantine, and phylax_report use the dispatch framework).

## Daemon Mode

The daemon provides a simple Unix domain socket interface for local tool integration.

### Socket Protocol

1. **Connect** to the Unix domain socket (default: `/tmp/phylax.sock`)
2. **Send** a file path as a newline-terminated string (max 4095 bytes)
3. **Receive** a JSON response
4. Connection is closed after each response (one request per connection)

### JSON Response Format

```json
{"findings":N,"status":"ok"}
```

Where `N` is the count of threat findings detected.

### Client Examples

```bash
# Using socat
echo "/path/to/suspicious.exe" | socat - UNIX-CONNECT:/tmp/phylax.sock

# Using netcat (BSD)
echo "/path/to/file" | nc -U /tmp/phylax.sock

# Programmatic (Python)
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/phylax.sock")
s.send(b"/path/to/file\n")
response = s.recv(4096)
s.close()
```

### Startup

```bash
phylax daemon
phylax daemon --socket /var/run/phylax.sock --rules /etc/phylax/rules.yar
```

The daemon removes any existing socket file on startup and cleans up on shutdown.

## CI/CD Pipeline

Phylax supports CI/CD integration with severity-based gating and SARIF output.

### Severity Threshold

Use `--severity-threshold` to set the minimum severity that triggers a non-zero exit:

```bash
# Fail only on HIGH or CRITICAL findings
phylax scan /build/output --severity-threshold high --exit-code 1

# Fail on any finding (INFO and above)
phylax scan /build/output --severity-threshold info
```

**Severity levels** (ascending): `info`, `low`, `medium`, `high`, `critical`

### Exit Code Control

The `--exit-code` flag sets the specific exit code returned when the threshold is met:

```bash
phylax scan /build --severity-threshold medium --exit-code 2
```

| Exit Code | Meaning |
|-----------|---------|
| 0 | No findings at or above threshold |
| N | Findings detected at or above threshold (N from `--exit-code`, default 1) |

### SARIF Output

Generate SARIF v2.1.0 reports for integration with GitHub Code Scanning, Azure DevOps, and other SARIF-compatible platforms:

```bash
phylax report /build/output --format sarif > results.sarif
```

### GitHub Actions Example

```yaml
- name: Scan build artifacts
  run: |
    phylax scan ./dist --severity-threshold high --exit-code 1

- name: Generate SARIF report
  if: always()
  run: |
    phylax report ./dist --format sarif > phylax.sarif

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: phylax.sarif
```

### GitLab CI Example

```yaml
threat-scan:
  stage: test
  script:
    - phylax scan ./build --severity-threshold medium --exit-code 1
  artifacts:
    reports:
      sast: phylax.sarif
    when: always
  after_script:
    - phylax report ./build --format sarif > phylax.sarif
```

### Jenkins Pipeline Example

```groovy
stage('Threat Scan') {
    steps {
        sh 'phylax scan ./target --severity-threshold high --exit-code 1'
    }
    post {
        always {
            sh 'phylax report ./target --format sarif > phylax.sarif'
            archiveArtifacts artifacts: 'phylax.sarif'
        }
    }
}
```
