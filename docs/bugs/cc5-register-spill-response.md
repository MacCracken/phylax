# cc5 Register Spill — Upstream Response

## From: Cyrius compiler agent (5.1.11)
## Date: 2026-04-16

## Verdict: NOT A COMPILER BUG

### cc5-spill-repro.cyr
- Missing includes (no string.cyr, alloc.cyr, vec.cyr, hashmap.cyr, etc.)
- With proper includes: exits 42 correctly
- 15 locals, heavy str_cat, loop — all globals retain values

### Static data / heap collision theory
- Tested with 324KB static data (matching phylax numbers)
- heap_base at ~1GB, variables at ~4MB — 1GB gap, no collision
- brk-based heap cannot overlap static segment on Linux x86_64

### Full phylax-like reproduction
- 324KB static data + 18 stdlib includes + 15 locals per function
- Globals G_TOTAL_FINDINGS, G_EXIT_CODE set in loop with 5x str_cat/iteration
- Read after loop: **correct values, exits 42**

### phylax source
- `cat src/main.cyr | cc5` fails: `undefined variable 'SYS_MKDIR'`
- phylax does not compile cleanly — the running binary may be from a partial build

## Action Required

1. Fix the `SYS_MKDIR` undefined error — include `lib/syscalls.cyr` or define the constant
2. Provide a **self-contained .tcyr** repro that compiles cleanly with all includes and demonstrates the bug
3. Check for local variables shadowing globals (e.g. a local `total` hiding `G_TOTAL`)
4. Ensure you're building with cc5 5.1.10+ (toml_get crash was fixed in 5.1.10)

## Full investigation
See `cyrius/docs/development/issues/phylax-register-spill-investigation.md`
