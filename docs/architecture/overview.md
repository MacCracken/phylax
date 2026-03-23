# Architecture Overview

## Design Principles

1. **Modular workspace** — each analysis capability is a separate crate
2. **Zero unsafe code** — memory safety throughout
3. **Extensible rules** — YARA-compatible TOML rule format
4. **AI-native** — designed for daimon orchestration and hoosh LLM triage
5. **MCP-first** — all capabilities exposed as MCP tools

## Module Map

```
phylax (CLI binary)
  │
  ├── phylax-core        Always available — types, errors, config
  ├── phylax-yara        Rule engine — literal, hex, regex patterns
  ├── phylax-analyze     Binary analysis — entropy, magic bytes, hashing
  ├── phylax-mcp         MCP tool definitions (5 tools)
  └── phylax-ai          Daimon registration + hoosh triage client
```

## Crate Dependencies

```
phylax-core  ←── phylax-yara
     ↑            ↑
     ├── phylax-analyze
     ↑
phylax-mcp  ←── (core, yara, analyze)
phylax-ai   ←── (core)
```

## Scan Pipeline

1. **File I/O** — read file, enforce `max_file_size`
2. **Magic bytes** — identify file type from header bytes
3. **SHA-256** — compute content hash
4. **Entropy** — Shannon entropy + block profile, flag suspicious (>7.5 bits/byte)
5. **Polyglot** — detect files matching multiple format signatures
6. **YARA scan** — match loaded rules against content
7. **Aggregate** — merge findings, sort by severity, report

## Consumers

- **daimon** — orchestrator registers phylax as a threat-scanning agent
- **hoosh** — LLM triage classifies findings for analyst review
- **MCP clients** — any MCP-compatible tool can invoke phylax capabilities
