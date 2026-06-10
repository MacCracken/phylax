# Dependency Watch

Status tracking for all dependencies. Current as of **phylax 1.2.0**
(2026-06-10).

## Cyrius Stdlib Modules (35)

Opt-in via `[deps] stdlib` in `cyrius.cyml` — stdlib modules are **not**
auto-resolved; an undeclared-but-referenced symbol compiles to a `ud2`
under cyrius 6.1.x and SIGILLs at runtime.

| Module | Purpose |
|--------|---------|
| `string` | C string utilities (strlen, streq, memcpy) |
| `fmt` | Number formatting (fmt_int, fmt_hex) |
| `alloc` | Heap allocator (bump + arena) |
| `vec` | Dynamic vectors |
| `str` | Str type (fat pointer: data+len) |
| `syscalls` | Linux syscall bindings |
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
| `freelist` | Free-list allocator |
| `bigint` | Arbitrary-precision integers |
| `http` | HTTP client |
| `mmap` | Memory mapping |
| `ct` | Constant-time primitives (sigil 3.x PQ + AES-GCM surface) |
| `keccak` | SHA-3 / SHAKE / Keccak-f1600 (sigil ML-DSA) |
| `random` | getrandom for keygen / nonces (sigil) |
| `slice` | Slice subscripts (`_slice_idx_get_W`; sigil 3.7.x via agnosys) |
| `thread_local` | Thread-local storage (sigil 3.7.x `cbank` crypto cache) |

> **Not declared (intentional):** `bayan` — sigil 3.7.x references
> `bayan_json_get` on a DCE-pruned/unreachable path phylax never calls.
> Declaring it pulls all of `bayan.cyr` in and overshoots the 2 MB
> non-DCE test binary cap. Deferred to **1.2.1**, gated on cyrius 6.1.27
> raising the cap. Until then it's a benign `undefined function` warning.

## External Dependencies

| Dependency | Version | Purpose | Notes |
|-----------|---------|---------|-------|
| `sakshi` | 2.2.10 | Structured logging | `dist/sakshi.cyr` bundle |
| `sigil` | 3.7.8 | Cryptographic primitives | SHA-256 (SHA-NI dispatch); only `sha256_hex` consumed |
| `majra` | 2.4.5 | Pubsub/counter | Transitive via bote `events_majra` |
| `bote` | 2.7.3 | MCP tool registry/dispatch | Full profile only |
| `libro` | 2.7.2 | Explicit pin for bote's transitive surface | Matches bote 2.7.3's own libro pin |

## Toolchain

- **Cyrius**: 6.1.25 (pinned in `cyrius.cyml`)
- **Next gate**: cyrius 6.1.27 — expected to raise the binary output cap
  and return the `bayan` dep, unblocking the 1.2.1 cut.

## Upgrade Notes

- Stdlib modules are bundled with the Cyrius toolchain — refresh the
  vendored `lib/` snapshot with `cyrius lib sync` after a toolchain pin
  bump, then `cyrius deps` to rehydrate the pinned git bundles.
- Dep tag bumps in `cyrius.cyml` must point to a GitHub-released tag,
  never a local repo's in-progress `VERSION`.
