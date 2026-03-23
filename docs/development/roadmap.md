# Roadmap

## v1.0.0 — Stability & Polish

### API
- [ ] Unified error strategy documentation
- [ ] `# Errors` doc sections on public Result-returning functions
- [ ] Document safety limit constants (256/1024/4096 iteration caps)

### Performance
- [ ] Reuse HTTP clients across daemon connections (currently one per connection)

### Testing
- [ ] Property-based tests for PE/ELF parsers (proptest)

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
