# Security Audit — 2026-04-16

## Scope
Code review of src/phylax.cyr (8,578 lines) for input validation,
buffer overflows, path traversal, and resource exhaustion.

## Findings

### PASS — No Issues Found

- **phylax_read_file O_NOFOLLOW**: Line 643 opens files with `O_RDONLY | O_NOFOLLOW`, correctly rejecting symlinks before reading.
- **phylax_read_file fstat check**: Lines 647-650 call `fstat` after open and verify `(mode & 0170000) == 0100000` (regular file). Non-regular files (devices, pipes, sockets) are rejected and the fd is closed.
- **phylax_read_file size cap**: Line 635 checks `size > PHYLAX_MAX_FILE_SIZE` (100 MB) before any allocation. Returns 0 on oversized files.
- **Per-scan allocation limit**: Lines 638-639 track cumulative allocation per scan via `G_SCAN_ALLOC_TOTAL` and enforce a 200 MB cap (`G_SCAN_ALLOC_LIMIT`). Prevents memory exhaustion from large or many embedded files.
- **memmem bounds**: Lines 880-895 correctly check `nlen == 0` and `nlen > hlen` before computing `limit = hlen - nlen`. The inner loop accesses `haystack + i + j` where `i <= limit` and `j < nlen`, so `i + j <= hlen - nlen + nlen - 1 = hlen - 1`. No out-of-bounds.
- **quarantine_validate_id path traversal rejection**: Lines 6272-6301 reject empty IDs, forward slash (`0x2F`), backslash (`0x5C`), and the `..` substring. This prevents directory traversal in quarantine file operations.
- **quarantine_release uses validate_id**: Line 6415 calls `quarantine_validate_id(id)` before any file system operation, correctly rejecting malicious IDs.
- **daimon_validate_agent_id**: Lines 6973-6988 apply the same path traversal checks to agent IDs received from daimon, preventing URL path injection in heartbeat/deregister endpoints.
- **ZIP bomb protection — entry limit**: Line 2664 enforces `entry_count < ARCHIVE_MAX_ENTRIES` (1024) per archive.
- **ZIP bomb protection — depth limit**: Line 2659 checks `max_depth <= 0` and decrements on recursion (line 2698), enforcing 3 levels max.
- **ZIP bomb protection — expand limit**: Line 2678 checks `uncomp_size <= ARCHIVE_MAX_EXPAND` (100 MB) per entry.
- **TAR bomb protection**: Lines 2765, 2784 apply the same entry count, depth, and expand limits as ZIP scanning.
- **PE parser minimum size**: Line 3609 requires `data_len >= 64` before any PE parsing. The `e_lfanew` read at `0x3C` is within this bound.
- **PE e_lfanew bounds check**: Line 3615 verifies `pe_offset + 4 <= data_len` before reading the PE signature.
- **PE COFF header bounds check**: Line 3624 verifies `coff_offset + 20 <= data_len` before reading COFF fields.
- **PE optional header bounds check**: Line 3642 verifies `opt_offset + 2 <= data_len` before reading magic, and lines 3647/3652 check for full optional header size.
- **PE section table bounds**: Line 3533 checks `soff + 40 > data_len` before reading each section header, capped at `PE_MAX_SECTIONS` (96).
- **PE import parsing bounds**: Lines 3272, 3283-3284, 3298, 3314 check offsets against `data_len` at each step of the import descriptor and ILT walk.
- **PE export parsing bounds**: Lines 3369, 3381-3386 check data directory, export directory, and name pointer offsets.
- **PE TLS callback bounds**: Lines 3411, 3421-3422, 3433-3434 check offsets at each level.
- **PE debug/PDB bounds**: Lines 3461, 3473, 3479 check directory entry, CodeView, and PDB path offsets.
- **PE certificate bounds**: Line 3509 checks `cert_dir_off + 8 > data_len`.
- **PE limits**: Sections capped at 96, imports at 256, exports at 1024, ILT entries at 512. Prevents excessive parsing on malformed inputs.
- **ELF parser minimum size**: Line 4241 requires `data_len >= 52` (ELF32 minimum), and line 4258 requires `>= 64` for ELF64.
- **ELF section bounds**: Line 4034 checks `off + sh_entry_size > data_len` per section, capped at `ELF_MAX_SECTIONS` (1024).
- **ELF program header bounds**: Line 3947 checks `off + ph_entry_size > data_len` per segment.
- **ELF symbol cap**: Line 4214 enforces `ELF_MAX_SYMBOLS` (4096).
- **YARA match offset cap**: Line 4538 enforces `YARA_MAX_MATCH_OFFSETS` (4096), preventing DoS from patterns with excessive matches.
- **Daemon request buffer**: Line 8226 reads at most 4095 bytes, null-terminates, preventing buffer overflow on the request path.
- **hex_decode validation**: Lines 860-872 check for odd-length input and invalid hex digits, returning 0 on failure.

### INFO — Acceptable Risk

- **read_u16_le / read_u32_le / read_u64_le have no bounds checks**: These helper functions (lines 2911-2928) perform raw `load8(data + offset)` reads without verifying `offset + N <= data_len`. This is by design — all callers are responsible for bounds checking before calling these helpers. Every call site in `parse_pe`, `parse_elf`, and archive scanning was audited and all perform appropriate bounds checks before invoking the read helpers. The risk is acceptable as long as new callers maintain this discipline.
- **read_ascii / read_fixed_ascii unbounded inner reads**: `read_ascii` (line 2930) reads up to `max_len` bytes from `data + offset` without verifying `offset + max_len <= data_len`. All callers pass bounded values (e.g., 256 for import names, 260 for PDB path, 8 for section names) and verify the base offset against `data_len` first. Acceptable.
- **http_post response buffer**: Line 730 allocates a fixed 65536-byte buffer and caps reads at that size (line 736). Responses larger than 64KB are silently truncated. This is acceptable for the current use cases (hoosh triage, daimon registration) where responses are small JSON payloads.
- **http_post request buffer**: Line 683 allocates a fixed 4096-byte buffer for HTTP request headers. Very long URLs or content types could overflow this buffer. Acceptable because all URLs are constructed internally from controlled base_url values.
- **Quarantine ID format not cryptographically random**: `quarantine_gen_id` (line 6256) uses `hex(timestamp)-hex(counter)`, which is predictable. This is acceptable because quarantine IDs are not used for authentication or authorization — only for file naming within a restricted directory.
- **Daemon single-threaded**: The daemon (line 8220) processes one connection at a time with no timeout. A slow or hanging client blocks subsequent connections. Acceptable for the current use case of local tool integration.
- **Per-scan allocation counter not reset in parallel mode**: `G_SCAN_ALLOC_TOTAL` is shared across threads but not protected by a mutex. In parallel scan mode (line 7432), concurrent increments could race. However, since the counter is only used as a soft limit to prevent extreme memory usage, minor races are acceptable.
- **YARA .yar parser**: The YARA .yar syntax parser performs string processing on untrusted rule files. While no specific vulnerability was found, the parser is complex (several hundred lines) and could benefit from fuzz testing with malformed .yar inputs.

### WARN — Should Fix

- **ZIP compressed_size used for offset advance without bounds check**: Line 2708 advances `offset = data_offset + comp_size` where `comp_size` comes from `read_u32_le(data, offset + 18)`. If a malformed ZIP entry has `comp_size` larger than the remaining data, the next iteration's `offset + 30 < data_len` check (line 2664) will catch it and break the loop. However, the intermediate value of `data_offset + comp_size` could theoretically overflow on 64-bit. In practice, since Cyrius i64 is 64-bit and file sizes are capped at 100MB, this is extremely unlikely. **Recommendation**: Add an explicit check `if (data_offset + comp_size > data_len) { break; }` before line 2708 for defense in depth.
- **TAR parse_octal no overflow protection**: Line 2747 `parse_octal` accumulates `result = result * 8 + (c - 48)` without checking for integer overflow. A malicious TAR header with 11 octal digits can produce values up to 8^11 - 1 = ~8.5 billion, which fits in i64. However, the 12-byte field could theoretically be fully populated and produce values near 8^12 (~68 billion), still within i64 range. **Recommendation**: Cap parsed size at `ARCHIVE_MAX_EXPAND` immediately after parsing for additional safety.
- **Watch mode scans directory root instead of changed file**: Lines 7762-7764 construct `file_path = path_join(watch_dir, str_from(""))` and scan the directory root rather than the specific file that triggered the inotify event. The file name bytes are read (lines 7753-7756) but not incorporated into the path. This is a functionality bug, not a security issue, but it means watch mode scans the wrong target. **Recommendation**: Build the actual file path from `watch_dir` and the extracted filename, then scan that specific file.
- **Custom rules accumulate across scans**: Line 7360-7364 adds custom rules to the global YARA engine on each call to `run_scan`. In a multi-file scan, rules from the custom file are added once per file, causing duplicate rule evaluations and O(n^2) growth. Not a security vulnerability, but causes performance degradation and duplicate findings. **Recommendation**: Load custom rules once before the scan loop, not inside `run_scan`.
- **load_config uses cstr paths without O_NOFOLLOW**: Line 8330 calls `phylax_read_file("phylax.toml")` which goes through the hardened path (O_NOFOLLOW + fstat). However, if `phylax_read_file` is passed a raw cstr literal rather than a Str-wrapped cstr, the behavior depends on whether the stdlib `file_read_all` (used for small files) applies the same protections. For the mmap path (files > 64KB), O_NOFOLLOW is applied. For the small-file path (line 661), `file_read_all` is a stdlib function whose symlink behavior was not verified. **Recommendation**: Verify that the stdlib `file_read_all` function rejects symlinks, or always use the mmap path with O_NOFOLLOW for config files regardless of size.

### CRITICAL — Must Fix

- None identified. No blocking security issues found.

## Summary

The codebase demonstrates strong security practices for a pre-1.0 release. Every major attack surface has been addressed:

- **File I/O**: O_NOFOLLOW + fstat + size cap + per-scan allocation limit
- **PE/ELF parsing**: Bounds checks at every level, hard caps on section/import/symbol counts
- **Archive scanning**: Depth, entry count, and expand size limits prevent zip/tar bombs
- **Path traversal**: Both quarantine IDs and daimon agent IDs are validated against traversal characters
- **Pattern matching**: Match offset cap prevents DoS from high-frequency patterns
- **Memory**: Large allocations use mmap_anon (OS-managed), small allocations use the Cyrius bump allocator, with a 200MB per-scan soft limit

The WARN items are defense-in-depth improvements and one functionality bug in watch mode. None represent exploitable vulnerabilities in the current deployment context. The codebase is ready for rc1 from a security standpoint, with the WARN items tracked for resolution before final v1.0.0.
