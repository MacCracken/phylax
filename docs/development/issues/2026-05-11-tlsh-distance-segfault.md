# tlsh_distance(h, h) segfaults under cyrius 5.10.44 + sigil 3.1.1

**Filed**: 2026-05-11 (phylax 1.1.1 sweep)
**Status**: Open — `assert_eq(tlsh_distance(h, h), 0)` disabled in `tests/test_tlsh.tcyr` pending fix
**Severity**: Functional (TLSH distance computation crashes the process); test-suite only — `tlsh_hash` itself works
**Affects**: `src/hashing.cyr` (TLSH implementation) under cyrius 5.10.44 toolchain + sigil 3.1.1 transitive

## Symptom

Calling `tlsh_distance(h, h)` with `h` a non-zero TLSH hash produced by `tlsh_hash(data, 256)` segfaults the process (exit 139, SIGSEGV). The function never returns; no assertion message prints because the crash precedes any stdout write inside the assertion macro.

Bisected via marker `syscall(SYS_WRITE, ...)` calls in `tests/phylax.tcyr:438-442`:

```
MARK8     ← last printed marker, immediately before `if (h != 0) { ... }`
[crash]   ← segfault inside `var dist = tlsh_distance(h, h);`
```

MARK9 (placed between the if-guard and the call's RHS) never fires, narrowing the crash to the `tlsh_distance` function body (not the if-guard or the RHS evaluation of `h`).

## Reproduction

Pre-split (against `tests/phylax.tcyr` on phylax 1.1.0 → 1.1.1 transition):

```bash
$ cyrius test tests/phylax.tcyr
=== severity ===
=== errors ===
...
=== tlsh ===
[exit 139]
```

`FAIL: phylax` + `test failures` print in CI but not locally (PIPESTATUS masking; raw `./build/phylax-test` shows exit 139).

Post-split (against `tests/test_tlsh.tcyr` with the segfault assertion commented out):

```bash
$ cyrius test tests/test_tlsh.tcyr
=== tlsh ===
5 passed, 0 failed (5 total)
```

To reproduce the crash, restore the commented block in `tests/test_tlsh.tcyr:25-29`:

```cyrius
# if (h != 0) {
#     var dist = tlsh_distance(h, h);
#     assert_eq(dist, 0, "identical tlsh distance = 0");
# }
```

## Suspected Root Cause

Not yet bisected past the function-body boundary. Candidates:

1. **cc5 register-spill regression** — phylax has a documented cc5 bug at `docs/bugs/cc5-register-spill.md`. The crash pattern (silent SIGSEGV mid-function, marker-print sensitive) is consistent with stack-corruption from spilled-register clobber. Adding `syscall(SYS_WRITE, ...)` markers around the crash site shifted register allocation enough to make the crash disappear in one bisect iteration (then return when markers were removed) — classic cc5-spill symptom.

2. **TLSH-side memory bug surfaced by 5.10.x layout changes** — `tlsh_distance` reads from the two hash pointers (`h`, `h2`). If the 64-bit TLSH hash returned by `tlsh_hash` isn't being stored / loaded the same way under cyrius 5.10.x's calling convention, the function could dereference a stale or truncated pointer. The 5.7.48 → 5.10.44 jump traverses the `lib/hashmap.cyr` heap-grow rounding fix (5.6.34), the `lib/syscalls_x86_64_linux.cyr` `sys_stat` / `sys_fstat` addition (5.8.6), and the `str_split` runtime-dispatch change (5.10.43) — any of those touching the layout `tlsh_distance` relies on.

3. **sigil 3.x SHA-256 interaction** — TLSH internally calls into the sigil bundle for partial hashing. The 2.9.5 → 3.1.1 jump pulls in the new PQ / AES-GCM transitive surface plus the `ct_eq_bytes_lens` / `_keccak_*` / `random_bytes` symbols. None of these are obviously on TLSH's hot path, but the bundle layout shifted by ~thousands of lines and the call-site offsets changed correspondingly. Listed for completeness; less likely than (1) or (2).

## Containment

Pre-split, this single crash poisoned the entire test run — the 16 test groups after `test_tlsh()` in `main()` never ran (`test_memmem`, `test_hex`, `test_report`, `test_tar_detection`, `test_archive_scanning`, `test_fingerprint`, `test_baseline`, `test_timestamp`, `test_config`, `test_parse_severity`, `test_pe_detection`, `test_elf_security`, `test_yara_engine`, `test_scan_pipeline`, `test_hex_decode`, `test_memmem_variants`, `test_severity_names`, `test_category_names`). CI reported `FAIL: phylax` with no other detail.

Post-split (1.1.1), the crash is contained to `tests/test_tlsh.tcyr` alone, with the offending assertion disabled. All other 14 test files (188 assertions total) run independently and pass.

## Closeout Criteria

- `tlsh_distance(h, h)` returns `0` without crashing on a known-good TLSH hash.
- The disabled block in `tests/test_tlsh.tcyr:25-29` is restored and `cyrius test tests/test_tlsh.tcyr` passes with the `"identical tlsh distance = 0"` assertion firing.
- Cross-check: bisect the cyrius toolchain pin between 5.7.48 (last known passing) and 5.10.44 (failing) to confirm whether the regression is cc5-side or TLSH-side. If cc5-side, fold into `docs/bugs/` as a paired bug filing.

## Related

- `docs/bugs/cc5-register-spill.md` — earlier cc5 register-spill bug filing; similar symptom shape.
- `docs/development/issues/2026-04-30-cyrius-stdlib-issues.md` — toolchain-side issue catalogue; cross-link if root cause turns out to be stdlib-side.
- CHANGELOG `[1.1.1]` Fixed section — references this file.
