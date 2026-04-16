# Dependency Watch

Status tracking for all dependencies.

## Cyrius Stdlib Modules (25)

| Module | Purpose |
|--------|---------|
| `string` | C string utilities (strlen, streq, memcpy) |
| `fmt` | Number formatting (fmt_int, fmt_hex) |
| `alloc` | Heap allocator (bump + arena) |
| `vec` | Dynamic vectors |
| `str` | Str type (fat pointer: data+len) |
| `syscalls` | Linux x86_64 syscall bindings |
| `io` | File I/O (open, read, write, close) |
| `args` | Command-line arguments |
| `assert` | Testing assertions |
| `hashmap` | Hash table (open addressing, FNV-1a) |
| `json` | JSON parser/serializer |
| `toml` | TOML parser |
| `regex` | Pattern matching |
| `fs` | Filesystem operations |
| `net` | TCP/UDP sockets |
| `tagged` | Option/Result types |
| `fnptr` | Function pointers |
| `callback` | Closure patterns |
| `thread` | Thread creation via clone(2) |
| `bench` | Benchmarking primitives |
| `bounds` | Boundary checking |
| `math` | f64 builtins |
| `process` | Process management |
| `chrono` | Time/date operations |
| `base64` | Base64 encoding |
| `csv` | CSV parsing |

## External Dependencies

| Dependency | Version | Purpose | Notes |
|-----------|---------|---------|-------|
| `sakshi` | 1.0.0 | Structured logging | Replaces Rust tracing/tracing-subscriber |
| `sigil` | 2.1.2 | Cryptographic primitives | SHA-256 for file hashing and imphash |

## Toolchain

- **Cyrius**: 5.1.3 (pinned in `.cyrius-toolchain`)
- **Minimum recommended**: 5.0.0 (IR, cyrius.cyml support)

## Upgrade Notes

- `sakshi` 1.0.0 is stable — no breaking changes expected
- `sigil` 2.x provides SHA-256, HMAC, and other cryptographic primitives
- Stdlib modules are bundled with the Cyrius toolchain — version tracks the compiler
