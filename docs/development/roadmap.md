# Roadmap

## v1.0.0 — Production

- [ ] API stability guarantee
- [ ] Multi-file and directory scanning (batch `phylax scan dir/`)
- [ ] Daimon agent lifecycle wiring (register on startup, heartbeat loop, deregister on shutdown)

## Non-goals

- Full antivirus engine (not a replacement for ClamAV)
- Network packet inspection (out of scope)
- Kernel-level monitoring (userspace only)
