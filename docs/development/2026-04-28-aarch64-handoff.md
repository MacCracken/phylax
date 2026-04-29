# 2026-04-28 — Handoff: aarch64 cross-build chain

Mid-session pause. Resume here when ready.

## Where things stand

| repo | branch state | pin state | git WT |
|---|---|---|---|
| **cyrius** | 5.7.34 released (cc5_aarch64 codebuf cap raised 524288 → 3145728 — Fix 1 of 3 done) | — | — |
| **agnosys** | 1.0.3 released (raw `syscall(SYS_OPEN, …)` → portable `sys_open(...)` at security.cyr:96) | cyrius pin 5.7.8 | clean, matches released 1.0.3 |
| **sigil** | last release: 2.9.4. main branch has `[deps.agnosys] tag = "1.0.3"` committed (`48e7ba2`) but **not yet tagged as 2.9.5** | cyrius pin 5.6.42 (stale; needs 5.7.34+) | clean |
| **phylax** | 1.1.0 in-flight | cyrius pin 5.7.34, sigil 2.9.4 (stale) | **17-file delta ready as one commit** — see below |

### Phylax working-tree (commit-ready as a single change)

```
M  CHANGELOG.md            # 1.1.0 verification block: 5.7.31 → 5.7.34
M  CLAUDE.md               # Language: Cyrius 5.7.34
M  cyrius.cyml             # cyrius = "5.7.34"
M  lib/math.cyr            # stdlib snapshot from cyrius deps refresh
M  src/{analyze,archive,cli,elf,hashing,integration,pe,script,yara}.cyr
                           # 5.7.34 fmt rule (8-space `if` continuation)
M  tests/{phylax,phylax-core}.tcyr   # same fmt rule
M  dist/phylax.cyr          # distlib regen mirrors src refmt
M  dist/phylax-core.cyr     # ditto
```

`git add . && git commit -m "bump cyrius 5.7.31 → 5.7.34 (refmt + dist regen)"` and phylax is current.

All gates green: 178/178 full tests, 11/11 core tests, vet clean, fmt clean, distlib freshness clean, security scan clean. aarch64 cross-build still blocked at agnosys's chain (see Phase 1 below); CI runners don't ship `cc5_aarch64` so this skips on stock CI.

## Remaining work — three phases, in order

### Phase 1 — agnosys 1.0.4 (the actual sweep)

Goal: agnosys self-contains aarch64 portability. No cyrius-side change required.

#### Diagnosis (verified 2026-04-28)

Three categories of issue, NOT all equally cyrius's fault:

**(a) Agnosys-side bugs — fix in agnosys:**

| symbol | sites | what's wrong | fix |
|---|---|---|---|
| `SYS_ACCESS` | 13 raw `syscall(SYS_ACCESS, …)` calls in tpm/dmverity/ima/luks | x86_64-only enum member from cyrius stdlib; aarch64 stdlib uses `SYS_FACCESSAT` | use stdlib's portable `sys_access(path, mode)` (defined on both arches) |
| `SYS_UNAME_NR=63` (in src/syscall.cyr SysNrExt enum) | 1 call site | hardcoded x86_64 number; on aarch64 syscall 63 is `read` — silent miscall, NOT compile failure | drop redundant local def; use stdlib `SYS_UNAME` (already 160 on aarch64) |
| `SYS_PRCTL=157` (SysNrExt) | 3 sites | hardcoded x86_64; aarch64 prctl is 167 | arch-conditional (see strategy below) |
| `SYS_SYSINFO=99` (SysNrExt) | 1 site | hardcoded x86_64; aarch64 sysinfo is 179 | arch-conditional |
| `SYS_GETTID=186` (SysNrExt) | 1 site | hardcoded x86_64; stdlib already has `SYS_GETTID=178` on aarch64 | drop redundant local def, use stdlib's |
| `SYS_SOCKET_NR=41` (audit.cyr enum) | 1 site | hardcoded x86_64; aarch64=198 | arch-conditional |
| `SYS_BIND_NR=49` | 1 site | hardcoded x86_64; aarch64=200 | arch-conditional |
| `SYS_SENDTO_NR=44` | 1 site | hardcoded x86_64; aarch64=206 | arch-conditional |
| `SYS_RECVFROM_NR=45` | 1 site | hardcoded x86_64; aarch64=207 | arch-conditional |
| `SYS_UNSHARE` | 1 site | x86_64=272, aarch64=97 | arch-conditional |

**(b) Cyrius stdlib gaps — agnosys redefines locally as workaround (legit lang-agent hygiene item, not blocking the agnosys fix):**

| symbol | sites in agnosys | x86_64 # | aarch64 # |
|---|---|---|---|
| `SYS_GETDENTS64` | 2 (drm.cyr) | 217 | 61 |
| `SYS_GETRANDOM` | 2 (luks.cyr) | 318 | 278 |
| `SYS_LANDLOCK_CREATE_RULESET` | 1 (security.cyr) | 444 | 444 |
| `SYS_LANDLOCK_ADD_RULE` | 1 | 445 | 445 |
| `SYS_LANDLOCK_RESTRICT_SELF` | 1 | 446 | 446 |

These are real Linux syscalls on aarch64; cyrius stdlib just doesn't expose them. Agnosys can define locally arch-conditional and proceed; cyrius can backfill the wrappers later as a hygiene pass.

**(c) Intentional AGNOS custom syscall — leave alone:**

- `SYS_AGNOS_AUDIT_LOG=520` in audit.cyr — same number on all arches, AGNOS-defined. Already correct.

#### Strategy decision before patching

Pick one, both work:

- **`#ifdef CYRIUS_ARCH_X86 / CYRIUS_ARCH_AARCH64`** at module scope around enum members. Same pattern `lib/atomic.cyr` uses inline. Keeps agnosys single-file. Verify it works at enum-member level (sakshi 2.1.0 noted in-fn-body conditionals were broken in 5.5.11; module-scope was fine. 5.7.34 should be cleaner.)
- **Peer files** (e.g. `src/syscall_x86_64.cyr` / `src/syscall_aarch64.cyr` with a dispatcher in `src/syscall.cyr`). Same pattern cyrius's own stdlib uses. More files but matches the established stdlib idiom.

#### Verification gates

Standalone agnosys build is the proof:

```
CYRIUS_DCE=1 cyrius build src/main.cyr build/agnosys              # x86_64 — must stay clean
CYRIUS_DCE=1 cyrius build --aarch64 src/main.cyr build/agnosys-aarch64  # was clean in 1.0.3 but only because DCE pruned the broken sites; should be clean WITHOUT DCE too post-sweep
cyrius test tests/tcyr/test_integration.tcyr                      # 234/234 should hold
cyrius distlib                                                    # regen dist/agnosys.cyr at v1.0.4
```

Then bump VERSION → 1.0.4 + CHANGELOG entry covering the full sweep narrative + tag/release.

### Phase 2 — sigil 2.9.5 (after agnosys 1.0.4 released)

Sigil's main has `[deps.agnosys] tag = "1.0.3"` already committed (`48e7ba2`) — it's a +1 bump:

- `cyrius.cyml`:
  - `[deps.agnosys] tag` → `"1.0.4"`
  - `[package].cyrius` → `"5.7.34"` (was `5.6.42` — way stale; this picks up the cc5_aarch64 codebuf raise)
- `cyrius deps` to refresh `lib/agnosys.cyr` symlink + lock
- `cyrius distlib` to regen `dist/sigil.cyr`
- Verify sigil's CI gates: smoke build, 23 tests, bench, fuzz, security; aarch64 cross-build should pass now (codebuf done, agnosys clean)
- Bump VERSION 2.9.4 → 2.9.5
- CHANGELOG entry (sigil's format is heavy on technical narrative — see existing 2.9.4 entry as template)

### Phase 3 — phylax 1.1.0 final (after sigil 2.9.5 released)

Tiny diff:

- `[deps.sigil] tag = "2.9.4"` → `"2.9.5"` in cyrius.cyml
- `cyrius deps`
- `cyrius distlib && cyrius distlib core`
- Full CI parity sweep — should be all-green including aarch64 cross-build now (locally; CI still skips on stock runners)
- Update CHANGELOG verification block — currently claims "All pass on Cyrius 5.7.34"; can extend to confirm aarch64 build now lands once verified
- Tag 1.1.0

## Lang-agent backlog (cyrius-side, separate work — does NOT gate the chain)

1. **Stdlib aarch64 syscall exposure gap** — `lib/syscalls_aarch64_linux.cyr` should expose `SYS_GETDENTS64`, `SYS_GETRANDOM`, `SYS_LANDLOCK_*` as enum members + provide `sys_getdents64`, `sys_getrandom`, `sys_landlock_*` portable wrappers. Currently consumers (agnosys, future others) have to redefine locally — violates the "stdlib is the platform abstraction" principle. Hygiene item.

2. **Duplicate-fn warnings on aarch64 cross-build** (`aes_ni_available`, `_aes_ni_cpuid_probe`, `aes256_encrypt_block_ni`) — cyrius team couldn't reproduce in 5.7.34's investigation; deferred to "agnosys-side investigation when the agent has the include context." Once Phase 1's agnosys sweep is in flight on a dev box, capture the include sequence and report back.

## Resume-here checklist

When picking this up next session:

1. `cd /home/macro/Repos/phylax && git status --short` — if 17-file delta is still un-committed, decide: commit it independently first, or roll into the 1.1.0 final tag once Phase 3 lands. Either works.
2. `cd /home/macro/Repos/agnosys && git status --short` — should be clean. Confirm before patching.
3. Decide arch-conditional strategy (`#ifdef` inline vs peer files) — see "Strategy decision" above.
4. Apply Phase 1 fixes per the agnosys-side table.
5. Build agnosys for both arches, run tests, regen dist, bump VERSION → 1.0.4, write CHANGELOG.
6. **STOP** — wait for user to tag/release 1.0.4 before Phase 2.
7. Phase 2 (sigil) → user releases 2.9.5.
8. Phase 3 (phylax 1.1.0 tag).

## Pointers

- Memory: `~/.claude/projects/-home-macro-Repos-phylax/memory/MEMORY.md`
  - feedback_owl_cyim — use owl/cyim, not Read/Edit/Write
  - feedback_pin_to_released — pin to GitHub releases not local VERSION
  - feedback_minimal_pin_bump — pin nudges touch manifest + CLAUDE.md only
- Cyrius 5.7.34 changelog (codebuf raise narrative + the duplicate-fn warning deferral) — `/home/macro/Repos/cyrius/CHANGELOG.md` ## [5.7.34]
- Phylax 1.1.0 in-progress changelog entry — `/home/macro/Repos/phylax/CHANGELOG.md` ## [1.1.0]
- Agnosys 1.0.3 changelog (the SYS_OPEN fix that already shipped) — `/home/macro/Repos/agnosys/CHANGELOG.md` ## [1.0.3]
