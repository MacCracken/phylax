# Dependency Watch

Status tracking for all dependencies. Current as of **phylax 1.2.0**
(2026-06-10).

## Cyrius Stdlib Modules (31)

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
| `freelist` | Free-list allocator |
| `http` | HTTP client |
| `mmap` | Memory mapping |
| `ct` | Constant-time primitives (sigil 3.x PQ + AES-GCM surface) |
| `keccak` | SHA-3 / SHAKE / Keccak-f1600 (sigil ML-DSA) |
| `random` | getrandom for keygen / nonces (sigil) |
| `slice` | Slice subscripts (`_slice_idx_get_W`; sigil 3.7.x via agnosys) |
| `thread_local` | Thread-local storage (sigil 3.7.x `cbank` crypto cache) |
| `bayan` | Data-format bundle (cyrius 6.1.25 carve) — json / toml / csv / base64 / bigint / cyml / u128, canonical `bayan_*` + legacy aliases |

> **The bayan carve (cyrius 6.1.25).** `json`, `toml`, `csv`, `base64`,
> `bigint` (+ `cyml`, `u128`) were removed from cyrius stdlib and folded
> into the single `bayan` sibling bundle. Those names no longer resolve
> standalone — **declaring `bayan` supplies all of them**, and phylax's
> existing `json_*` / `toml_*` / `base64_*` / `csv_*` / `bigint` call
> sites keep working through bayan's back-compat aliases. Replacing the
> five carved modules with `bayan` is roughly size-neutral (the DCE
> binary actually shrank 1.98 MB → 1.78 MB); it also resolves the
> `bayan_json_get` symbol the sigil bundle references.

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
- **Watch**: ganita (math-domain) carve lands at cyrius 6.1.26, mirroring
  the bayan pattern. phylax uses only f64 primitives (kept in stdlib), so
  no migration is expected — confirm on the 6.1.26 bump.

## Upgrade Notes

- `lib/` is a **derived artifact** (gitignored). The dep contract is
  `cyrius.cyml` + `cyrius.lock`; `cyrius deps` rehydrates `lib/` against
  the pinned toolchain snapshot (stdlib, incl. `bayan`) plus the pinned
  git bundles. After a toolchain pin bump, a clean rehydration is
  `rm -rf lib && cyrius deps` (this is what CI/Release now do) — a stale
  `lib/` shadows the snapshot and breaks resolution when stdlib modules
  move (as the bayan carve did).
- Dep tag bumps in `cyrius.cyml` must point to a GitHub-released tag,
  never a local repo's in-progress `VERSION`.
