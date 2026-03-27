# Roadmap

## v0.6.0

### YARA
- YARA module system: `import "pe"` / `import "elf"` with structured access in conditions

### UX / CLI
- Config file support (`phylax.toml`, `$XDG_CONFIG_HOME/phylax/config.toml`)
- Progress indicator for multi-file scans (`indicatif`, feature-gated)
- `phylax rules fetch <source>` — download community rulesets

### Integration
- STIX/TAXII threat intel import (`phylax intel import --stix <file>`)
- MalwareBazaar SHA-256 hash feed (`phylax intel update`)
- Archive recursive scanning (ZIP/GZIP/TAR) with bomb protection

### Performance & Hardening
- Memory-mapped I/O for files > 4 MB (`memmap2`)
- `O_NOFOLLOW` + `fstat` hardening in scan path (Linux-specific)
- Per-scan allocation limits (cap total memory per scan)
- Daemon rate limiting and max concurrent scans

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
- WASM plugin system (reconsider post-v1)
