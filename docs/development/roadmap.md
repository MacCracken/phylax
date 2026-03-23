# Roadmap

## v1.0.0 — Production

- [ ] API stability guarantee
- [ ] Multi-file and directory scanning
- [ ] Watch mode (inotify/kqueue)
- [ ] Daimon agent lifecycle (register, heartbeat, deregister)
- [ ] Hoosh LLM triage integration
- [ ] Bote MCP tool registration (phylax_scan, phylax_rules, phylax_status, phylax_quarantine, phylax_report)
- [ ] Performance targets: >100 MB/s entropy, >50 MB/s full pipeline

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
