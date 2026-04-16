# cc5 Bug — Global Variable Corruption in Large Programs

## Summary

Global variables set inside a function are read back as 0 when the function has many local variables and calls many stdlib functions (especially `str_cat`, `str_from`, `str_println`). The globals are correct inside the loop but read as 0 when accessed later in the same function or passed to another function.

## Root Cause (suspected)

**Static data / heap collision.** The program has 324KB of static data (string literals, Pearson table, etc.). The bump allocator heap and the static data segment may overlap when both are large, causing `str_cat`/`str_from` allocations to overwrite global variable storage.

Evidence:
- `G_TOTAL_FINDINGS` prints correctly as 1 via `print_int` during the loop
- After loop completion + several `str_println`/`str_cat` calls, `G_TOTAL_FINDINGS` reads as 0
- Moving the check before print calls: still 0 (globals already corrupted by loop's print calls)
- Extracting logic to a small helper function: helper receives 0 (globals already 0 at call site)
- Standalone test with same globals + helper: works perfectly (exits 42)
- The program has `warning: large static data (324384 bytes)` — close to heap region

## Reproduction

The bug requires ALL of:
1. Large static data section (>300KB — from many string literals + lookup tables)
2. Many global variables
3. A function with 10+ locals
4. A loop body with 3+ `str_cat`/`str_from`/`str_println` calls per iteration
5. Global variable reads after the loop

Minimal repro not yet isolated — the bug does NOT trigger in small programs even with many locals.

## Affected in phylax

- `cmd_scan()` — `--severity-threshold` / `--exit-code` feature. Globals `G_TOTAL_FINDINGS`, `G_EXIT_CODE` etc. are correctly set in the scan loop but read as 0 afterward.
- Workaround attempted: small helper functions, pre-capture locals, moved checks before prints — none work because globals are already corrupted by loop body's print calls.

## Where to look in cc5

1. **Heap map** (`src/main.cyr` authoritative offset registry) — verify heap base doesn't overlap static data when static section exceeds ~300KB
2. **Static data layout** (`src/backend/x86/fixup.cyr`) — check `.data` section placement relative to `.bss` and heap start
3. **`alloc` implementation** (`lib/alloc.cyr`) — verify brk-based heap start accounts for large static sections
4. **Compiler warning** `large static data (324384 bytes)` — this is the trigger. Programs with <300KB static work fine.

## Test

```bash
# In phylax repo:
./build/phylax scan /tmp/test_elf.bin --severity-threshold info --exit-code 42
echo $?
# Expected: 42 (finding >= info threshold)
# Actual: 0 (globals corrupted)
```
