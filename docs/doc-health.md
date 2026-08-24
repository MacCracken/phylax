---
name: Phylax Documentation Health
description: Living ledger of doc currency in the phylax repo — fresh / stale / read-through / evergreen / frozen, refreshed as docs are touched
type: state
---

# Documentation Health — phylax

> **Last refresh**: 2026-08-23 (**1.2.6 P(-1) closeout** — VERSION 1.2.5 → 1.2.6, `[Unreleased]` folded into the 1.2.6 stanza, dist bundles rebuilt at v1.2.6. Three structural items: (1) **untrusted-input hardening** — a hostile-input sweep found 17 of 29 public entry points segfaulting on a null buffer/handle, and a guard-page fuzz found a real **OOB read in `read_strtab_entry`** (upper-bound-only check let a negative file-derived offset read BELOW the buffer); ~20 offset tests in `pe.cyr`/`elf.cyr` now route through a shared `in_bounds`. (2) **three phylax-local helpers namespaced** (`hex_encode`/`str_to_int`/`str_contains` → `phylax_*`) — `hex_encode` returned a `Str` where sigil's returns a cstr and phylax's won under last-definition-wins, inside sigil's own `sha256_hex`; phylax-side duplicate-fn warnings 6 → 0. (3) **tlsh_distance issue closed** — does not reproduce on 6.5.35. NEW: `tests/test_hardening.tcyr` (57 assertions) and `docs/adr/0002-untrusted-input-contract.md`. Suite 342 → **404 across 18 files**. Lint 33 → 8 (remaining are indivisible string literals). ⚠ One measured cost recorded rather than hidden: `shannon_entropy`'s null test is **+1.95 us/call** (code layout, not work — A/B'd; wrapper/reorder/merge all failed to recover it), kept deliberately. Prior refresh 2026-08-23 at the 1.2.5 cut.) | **Refresh cadence**: when docs are touched, update the affected row. No release attachment.
> **Pending refresh**: the 1.2.5 crash-fix pass (report renderers + CLI argv paths) added `docs/adr/` — previously "no ADRs yet" — with [`adr/0001-string-and-json-representation-boundaries.md`](adr/0001-string-and-json-representation-boundaries.md), and rewrote `docs/guides/testing.md` (was listing the removed `tests/phylax.tcyr` and a 16-group table; now per-module with the two new files) plus the `CLAUDE.md` test-count block. `CHANGELOG.md` carries an `[Unreleased]` stanza. The buckets below have not been re-tallied for these.
> **Scope**: This repo only (`phylax`) — root-level files (README, CHANGELOG, CLAUDE.md, etc.) plus the entire `docs/` tree, plus the two top-level `bench-latest.md` / `benchmarks-rust-v-cyrius.md` snapshots. Cross-repo dep / pin drift lives in [`development/dependency-watch.md`](development/dependency-watch.md), not here.

This is a **ledger**, not a one-time audit. Rewrite-in-place as docs change. Phylax is the threat-detection engine for the AGNOS first-party tree (daimon for scan integration, aegis for quarantine, t-ron as the output-scanning complement); stale module / PE-ELF / YARA / scoring docs propagate downstream as consumer-side mis-integrations, so doc currency carries weight. The doc surface is moderate (~20 files) and most are load-bearing.

Pattern lifted from the libro + majra ledgers ([`libro/docs/doc-health.md`](https://github.com/MacCracken/libro/blob/main/docs/doc-health.md), [`majra/docs/doc-health.md`](https://github.com/MacCracken/majra/blob/main/docs/doc-health.md)) — same buckets, phylax-shaped tiers (no ADRs yet; an audit tier exists, frozen by design; bench snapshots live at root rather than under `docs/`).

---

## At a glance — 2026-05-11 inventory

**~20 markdown files** total (8 root + 2 top-level bench snapshots + 12 under `docs/`). Buckets after the 2026-05-11 toolchain + dep pin sweep:

| Bucket | Count | What it means |
|---|---|---|
| 🟡 **Stale — refresh in place** | 2 | `docs/development/2026-04-28-aarch64-handoff.md` (pre-bump snapshot — see read-through note); `docs/development/issues/2026-04-30-cyrius-stdlib-issues.md` (walk-through owed against the 5.10.44 → 6.1.27 stdlib). `dependency-watch.md` was 🟡 and is now ✅ 1.2.0-fresh. |
| 🟠 **Read-through outstanding** | 2 | `docs/architecture/overview.md` (verify module map still matches `src/lib.cyr` ordering — no code moved, but a read-through is owed); `docs/development/threat-model.md` (verify trust-boundary claims still apply against sigil 3.7.x's PQ surface — phylax uses only SHA-256 hex, so should be a no-op, but a confirmation read-through is owed). `README.md` was 🟠 and is now ✅ 1.2.0-fresh. |
| ✅ **Fresh — touched in this sweep or current as written** | 8 | `cyrius.cyml` (pins bumped this sweep); `CHANGELOG.md` (1.2.0 stanza landed 2026-06-10); `CLAUDE.md` (toolchain + dep version block matches the 1.2.0 pins); `VERSION` (`1.2.0` — single source of truth); `README.md` (dep block + build stats refreshed at the 1.2.0 cut); `dependency-watch.md` (pin matrix rewritten this sweep); `.github/workflows/ci.yml` + `release.yml` (dep-resolve step now `rm -rf lib && cyrius deps` for the bayan carve); `doc-health.md` (this file, refreshed at the 1.2.0 cut). |
| 🔵 **Probably evergreen** | 4 | `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, `CONTRIBUTING.md`. No version-tied claims that drift between minor releases. Re-read annually. |
| 📦 **Date-stamped historical record** | 5 | `docs/audit/2026-04-16-security-audit.md` (1.0.x security-audit pass — date in filename, frozen); `docs/bugs/cc5-register-spill.md` + `docs/bugs/cc5-register-spill-response.md` (cc5 toolchain-side bug + upstream response — frozen, point-in-time); `docs/development/2026-04-28-aarch64-handoff.md` (aarch64 handoff snapshot — content is fresh-as-written but the *project state* it described has moved on, so it now functions as a frozen historical record + needs a read-through to confirm posture); `bench-latest.md` + `benchmarks-rust-v-cyrius.md` at root (rust-vs-cyrius is the HEADLINER — frozen; `bench-latest.md` is opportunistically refreshed but treated as a snapshot, not a ledger). |
| ❓ **Open strategic question** | 0 | See [Open questions](#open-strategic-questions) for what would re-open. |

**Toolchain + dep sweep completed 2026-05-11** (ship-cut at 1.1.1):

- ✅ `cyrius.cyml` — Cyrius pin 5.7.48 → 5.10.44; sakshi 2.1.0 → 2.2.4; sigil 2.9.5 → 3.1.1; majra 2.4.1 → 2.4.4; bote 2.5.1 → 2.7.1. Added direct `[deps.libro] = 2.6.3` override (bote-2.6.3+ pulls libro-2.6.2 transitively; libro-2.6.2 has a stale bare `ct_eq` call that the new stdlib's `ct.cyr` doesn't expose). Added `ct`, `keccak`, `random` to `[deps].stdlib` (new transitive surface from sigil 3.x's PQ + AES-GCM paths). All tags verified as published on the upstream remotes.
- ✅ `CLAUDE.md` — Project Identity language version bumped 5.7.34 → 5.10.44; Dependencies block bumped to match the new pins (sakshi 2.2.4 / sigil 3.1.1 / majra 2.4.4 / bote 2.7.1).
- ✅ `.gitignore` — `/lib/` added; the resolved deps directory is no longer tracked. Contract moves to the pin set in `cyrius.cyml`, the bytes get rehydrated by `cyrius deps`. Pattern lifted from libro + majra, where the same model has been in place for several minor cycles.
- ✅ `lib/` removed from the working tree — 63 previously-tracked vendored files. Next consumer run rehydrates from the new pins. (Maintainer needs a one-time `git rm -r --cached lib/` to flush the index — gitignore patterns don't retroactively untrack content.)
- ✅ `.github/workflows/ci.yml` — Format check step fixed: dropped `--check` flag in the `cyrius fmt` invocation. cyrius 5.10.x's `--check` is silent on clean files (exit 0, no output), so the prior `diff -q <(cyrius fmt "$f" --check) "$f"` produced a false positive on every non-empty file in the tree. `cyrius fmt "$f"` without flags emits the formatted source and the diff catches real drift only.
- ✅ `VERSION` — `1.1.0 → 1.1.1` (toolchain + dep sweep release).
- ✅ `CHANGELOG.md` — `[1.1.1] - 2026-05-11` stanza landed, capturing the toolchain bump, dep matrix, libro 2.6.3 direct-override rationale, stdlib additions, lib/ contract change, CI fmt fix, and the doc-health.md ledger introduction. Carryover (🟡 / 🟠) rows from this file documented in the stanza's "Carryover" section.
- ✅ `docs/doc-health.md` — this file, scaffolded as the initial audit and refreshed at the 1.1.1 cut.

**Carryover items the 1.1.1 sweep did not address** (these are the 🟡 / 🟠 rows above + the known-issue list in the CHANGELOG; flagged here so the next doc-touch session has a punch list):

- `docs/development/dependency-watch.md` — rewrite the pin matrix against the post-sweep state (cyrius 5.10.44, sakshi 2.2.4, sigil 3.1.1, majra 2.4.4, bote 2.7.1, +libro 2.6.3 direct override, +`ct` / `keccak` / `random` stdlib additions).
- `docs/development/roadmap.md` — refresh the aarch64-chain row (memory-tracked: agnosys 1.0.4 → sigil 2.9.5 → phylax 1.1.x portability sweep — sigil is now at 3.1.1 transitively; the chain shape needs an update).
- `docs/development/issues/2026-04-30-cyrius-stdlib-issues.md` — confirm which listed gaps closed at 5.10.44 (`lib/syscalls_x86_64_linux.cyr` in the 5.10.44 stdlib snapshot now defines `sys_stat` / `sys_fstat`, so phylax's `src/syscall_x86_64_linux.cyr` x86 backfill is at minimum redundant — duplicate-fn warnings surface but build is otherwise clean). Tracked for the 5.11.x / 5.12.x sweep alongside other phylax-side duplicate-fn cleanup (`str_to_int`, `hex_encode`, `hex_decode`, `str_contains` in `src/utils.cyr`).
- ✅ ~~`tests/phylax.tcyr` — `sha256 empty` assertion fails~~ — **fixed** in the 1.1.1 cut: rewrote `file_sha256` in `src/analyze.cyr` to bypass sigil's `sha256_hex` and compose `sha256()` + phylax's local `hex_encode()` directly; the three other call sites (`types.cyr:finding_fingerprint`, `src/integration.cyr` entropy path, `src/quarantine.cyr` file-quarantine path) now route through `file_sha256` instead of calling `sha256_hex` directly. Surfaced cleanly during the test split — `test_sha256.tcyr` and `test_integration.tcyr:test_fingerprint` both failed independently before the fix, both pass after. Dispatch collision is no longer reachable from phylax code.
- ✅ ~~`hex_decode` name collision~~ — **fixed** in the 1.1.1 cut: renamed phylax's `src/utils.cyr` `hex_decode(s, out_len_ptr)` → `phylax_hex_decode(s, out_len_ptr)` to break the collision with sigil's `hex_decode(hex_str, hex_len): i64` (different signature, same name; the linker was binding sigil's version at the test surface, leading to a Str-as-raw-ptr deref crash). Three call sites updated: `src/hashing.cyr:640-641` and `tests/test_utils.tcyr`. Same pattern likely needed for `hex_encode` / `str_to_int` / `str_contains` — folded into the broader duplicate-fn cleanup below.
- ✅ ~~aarch64 release-build undefined `SYS_MKDIR`~~ — **fixed** in the 1.1.1 cut: replaced raw `syscall(SYS_MKDIR/SYS_RENAME/SYS_UNLINK/SYS_INOTIFY_INIT/SYS_INOTIFY_ADD_WATCH, …)` calls across `src/quarantine.cyr` + `src/cli.cyr` with portable wrappers (`sys_mkdir`, `sys_unlink`, `sys_inotify_init`, `sys_inotify_add_watch` from the cyrius stdlib's per-arch peer; `sys_rename` is a new phylax-side backfill in both arch peer files since neither stdlib peer ships one). The aarch64 peer file `src/syscall_aarch64_linux.cyr` went from "intentionally empty" to a real backfill mirroring the x86 peer's role. Both arches build clean.

---

## Tier 0.5 — Decision records

| File | Last touched | Status | Notes |
|---|---|---|---|
| `adr/0001-string-and-json-representation-boundaries.md` | 2026-08-23 | ✅ Fresh | The cstr-vs-`Str` and `json_build`-vs-`json_v_*` contracts, written from the 1.2.5 crash-fix pass. |
| `adr/0002-untrusted-input-contract.md` | 2026-08-23 | ✅ Fresh | The 1.2.6 closeout contract: public entry points return their empty-case sentinel for bad input and never dereference; every file-derived offset test goes through `in_bounds`; phylax defines no bare name a dependency also defines. Carries the sentinel table, the `shannon_entropy` cost measurement, and the verification counts (6,306 guard-page combinations). |

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-08-23 | ✅ Fresh | Dependency pins block refreshed at the 1.2.5 cut (cyrius 6.5.35; sakshi 2.4.11 / sigil 3.12.9 / majra 2.7.0 / bote 3.3.7 / libro 2.8.12). sakshi + sigil now labelled **folded stdlib modules, not git deps**, and the stdlib count moved 32 → 34. Build-stats figures below the pins block still date from the 1.2.0 cut — refresh opportunistically. |
| `CHANGELOG.md` | 2026-08-23 | ✅ Fresh | Source of truth. `[1.2.6] - 2026-08-23` is the P(-1) closeout: Breaking (three `phylax_*` renames), Security (the ELF OOB read + 17 null-input crashes), the tlsh issue closure, and a **Performance** section that records `shannon_entropy`'s +1.95 us/call guard cost with the A/B evidence rather than burying it. The former `[Unreleased]` crash-fix stanza is folded in beneath it and released for the first time. `[1.2.5]`'s "Known, not fixed" note now points forward at the fix. |
| `CLAUDE.md` | 2026-08-23 | ✅ Fresh | Test counts refreshed to 404 across 18 files at the 1.2.6 closeout; `utils.cyr` module row now names the `in_bounds` offset validator. Dependency block still current from the 1.2.5 sweep. Rest is durable rules. |
| `CONTRIBUTING.md` | 2026-04-30 | 🔵 Evergreen | Generic contributor workflow. No version-tied claims. |
| `SECURITY.md` | 2026-04-30 | 🔵 Evergreen | Reporting policy + scope. No version-tied claims. |
| `CODE_OF_CONDUCT.md` | 2026-04-30 | 🔵 Evergreen | Standard. |
| `VERSION` | 2026-08-23 | ✅ Fresh | `1.2.6`. The `src/types.cyr` twin was bumped with it and is CI-gated against this file (added at 1.2.5 after it silently lagged two releases). |
| `LICENSE` | (initial commit) | 🔵 Evergreen | GPL-3.0-only. |

---

## Tier 2 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-08-23 | 🟠 Read-through | Dependency table refreshed at the 1.2.5 cut — it had been stale since the 5.1.7 / sakshi 1.0.0 / bote 2.5.1 era, several majors behind, and now carries a Kind column (folded stdlib vs git dep) plus a pointer to `dependency-watch.md` as canonical. Module map + data-flow diagrams still want a read-through against the current `src/lib.cyr` order. |

---

## Tier 3 — Development (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-08-23 | ✅ Fresh | Gained a **v1.2.6 — P(-1) Closeout** completed entry; the JSON/SARIF renderer item is struck as resolved. Dep-pruning item still open and still carries the measurement that deleting the vestigial majra/libro blocks makes things worse. |
| `dependency-watch.md` | 2026-08-23 | ✅ Fresh | Pin matrix rewritten against the 1.2.5 sweep (cyrius 6.5.35 / sakshi 2.4.11 / sigil 3.12.9 / majra 2.7.0 / bote 3.3.7 / libro 2.8.12). Gained three durable sections: why the **folded-module declaration shape** matters (sidecars went 1 leaf → 32/15), the **`stdlib`-array comment-parsing trap** (a `[` truncates the array, a `"quoted phrase"` becomes a module), and **Known dep-shape cost** (libro's git sigil double-stages ~350 KB). Toolchain section now warns on the 6.5.28 `fmt` and 6.5.19 bench-harness breaking changes. |
| `threat-model.md` | 2026-04-30 | 🟠 Read-through | Trust-boundary claims need a no-op confirmation against sigil 3.x — phylax consumes only `sha256_hex` (a stable surface that exists unchanged from sigil 2.x → 3.x), so no model drift is expected. Read-through to verify and re-stamp. |
| `2026-04-28-aarch64-handoff.md` | 2026-04-30 | 📦 Frozen + read-through | Aarch64 handoff snapshot — content is point-in-time. Read through once to confirm whether the listed handoff items are now resolved (sigil-side moved past 2.9.5 to 3.1.1; some aarch64-chain items may have closed transitively). If still open, leave as frozen and link the live status from `roadmap.md`. |

---

## Tier 4 — Development issues (`docs/development/issues/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `2026-04-30-cyrius-stdlib-issues.md` | 2026-04-30 | 🟠 Read-through | Catalogue of cyrius-stdlib gaps observed at the 5.7.48 floor. The 2026-05-11 sweep moved to 5.10.44 — `sys_stat`/`sys_fstat` now ship in the stdlib's `lib/syscalls_x86_64_linux.cyr` (verified). Walk the list: mark closed items, retire phylax-side workarounds (`src/syscall_x86_64_linux.cyr` x86 backfill is now redundant), file new issues for anything that resurfaced. |
| `2026-05-11-tlsh-distance-segfault.md` | 2026-05-11 | ✅ Fresh | New filing at the 1.1.1 cut. `tlsh_distance(h, h)` segfaults (exit 139) under cyrius 5.10.44 + sigil 3.1.1. The post-test-split monolithic-file replacement contains the failure to `tests/test_tlsh.tcyr` alone with the offending assertion commented out. Includes the bisect output + three candidate root causes (cc5 register-spill, 5.10.x layout, sigil 3.x interaction) + closeout criteria. Cross-linked from CHANGELOG 1.1.1 Known-issues. |

---

## Tier 5 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `cli-reference.md` | 2026-04-30 | ✅ Fresh (as written) | CLI subcommand surface. No version-tied claims that drift between minor releases; refresh when subcommands are added/retired. |
| `integration.md` | 2026-04-30 | ✅ Fresh (as written) | Consumer integration patterns (daimon, aegis, t-ron). Refresh when the `[lib]` / `[lib.core]` profile boundaries change or when a new consumer onboards. |
| `testing.md` | 2026-04-30 | ✅ Fresh (as written) | Test categories + assertion counts (178 across the full suite, 11 across the core smoke test). Refresh on assertion-count drift only when it crosses ~10%. |

---

## Tier 6 — Audit (`docs/audit/`)

Date-stamped point-in-time reports, frozen by design. Each audit pass gets its own file — the date is in the filename. Don't refresh in place.

| File | Pinned at | Status | Notes |
|---|---|---|---|
| `2026-04-16-security-audit.md` | 1.0.x | 📦 Frozen | Pre-1.1.0 security-audit pass — entropy / bounds / hashing surface. Findings are tracked downstream in CHANGELOG entries + `docs/development/roadmap.md`. Don't rewrite; the next audit gets its own date-stamped file. |

---

## Tier 7 — Bugs (`docs/bugs/`)

Cyrius-side bug filings (paired with upstream responses), frozen by design.

| File | Pinned at | Status | Notes |
|---|---|---|---|
| `cc5-register-spill.md` | cc5 (cyrius 5.x backend) | 📦 Frozen | Filing of the cc5-line register-spill issue from a phylax workload. |
| `cc5-register-spill-response.md` | cc5 | 📦 Frozen | Paired upstream response. Together these two are the historical record of the bisect + resolution. |

---

## Tier 8 — Benchmarks (root-level)

Date / version-stamped snapshots, frozen by design. Each major perf cutover gets its own file; older snapshots stay verbatim. Live bench history lives in `bench-history.csv` (gitignored).

| File | Pinned at | Status | Notes |
|---|---|---|---|
| `benchmarks-rust-v-cyrius.md` | port cutover | 📦 Frozen — HEADLINER | Rust → Cyrius port comparison. Heritage artifact; deliberately kept at repo root. Don't refresh in place. |
| `bench-latest.md` | 2026-03-26 | 🟡 Stale | Still the Rust-era criterion table (`entropy/shannon/1024`, `file_detection/detect_type_elf` …) — those benchmark names no longer exist in this tree, which runs 12 cyrius benches. NOT regenerated at the 1.2.5 cut on purpose: `scripts/bench-history.sh` overwrites this file from a gitignored `bench-history.csv`, so a run here would replace the historical table with a single-column one. Needs a deliberate decision — either seed the CSV and accept the reset, or retire this file in favour of the CHANGELOG's per-release tables. ⚠ Any comparison against it must also account for the 6.5.19 bench-harness change. |

---

## What this repo does NOT have yet (and doesn't need to invent)

The agnosys + libro ledgers have tiers for **ADRs**, structured **audit cadence**, and **engineering reviews**. Phylax has *some* of those structures, by design:

- **No ADRs yet.** Decision velocity is low; rationale rides CHANGELOG entries + roadmap notes + design comments. The 1.1.0 `[lib]` / `[lib.core]` split, the bote/majra transitive trim, and the per-arch syscall peer-file pattern were all candidates and none earned an ADR — the entries in CHANGELOG carry the reasoning. Open the directory only when a decision is reversible-but-load-bearing and would benefit from a referenceable "we decided X because Y" artifact.
- **Audit tier already exists, deliberately frozen-by-date.** `docs/audit/2026-04-16-security-audit.md` is the first entry. The next audit gets its own date-stamped file — never rewrite an audit in place.
- **No `docs/development/reviews/` cadence.** Internal review artifacts would emerge if and when audit cadence picks up. Not opened yet; not needed.
- **`docs/development/issues/` is open** — captures phylax-internal blockers that don't belong upstream. Issues *upstream* (cyrius / sigil / agnosys) are filed in their respective repos; phylax's roadmap cross-references them.
- **No `docs/standards/` directory yet.** Phylax conforms to several external specs (SARIF v2.1.0 in `report.cyr`, YARA module syntax, ssdeep CTPH formula). Today those citations live in module headers + `docs/architecture/overview.md`. Open `docs/standards/` only if a consumer asks for a structured conformance artifact.

---

## Open strategic questions

None outstanding for the 2026-05-11 sweep. This section will repopulate when:

- A new doc category appears (e.g. an `adr/` if a reversible architectural decision needs a referenceable record, or `standards/` if a consumer asks for SARIF / YARA / ssdeep conformance docs).
- The post-sweep refresh of `dependency-watch.md` + `roadmap.md` surfaces a cross-repo decision (e.g. whether the sigil 3.x adoption pulls phylax into the PQ surface story; today phylax consumes only `sha256_hex` and the answer is "no, but read-through to confirm").
- `bench-latest.md`'s snapshot model breaks down — if multiple readers want stable historical numbers, switch to a date-stamped `bench-snapshots/` directory like majra's `docs/benchmarks/`.

---

## In-flight (blocked, not stale)

- **aarch64 release chain** — memory-tracked: agnosys 1.0.4 → sigil 2.9.5 → phylax 1.1.x portability sweep. The sigil floor moved to 3.1.1 transitively in the 2026-05-11 sweep; the chain shape needs to be re-anchored on the post-sweep state. `docs/development/roadmap.md` refresh + `docs/development/2026-04-28-aarch64-handoff.md` read-through will rebuild the picture. No consumer asks for an aarch64 phylax binary today; passive tracker.
- **cyrius-stdlib include-ordering on 5.10.x** — the 2026-05-11 sweep surfaced an `undefined variable 'SYS_STAT'` compile error in `src/syscall_x86_64_linux.cyr:19`. Independent of the dep bumps; tracks to how the 5.10.x stdlib injects `lib/syscalls_x86_64_linux.cyr` relative to phylax's own `include`s. Owed as a follow-up; not blocking the doc-health.md scaffold.
- ✅ ~~**sigil 3.x asm-offset risk on NI paths**~~ — **resolved at the 1.2.0 cut.** The predicted SHA-NI SIGILL *did* fire (`tests/test_sha256.tcyr` exit 132 on sigil 3.7.8 + cyrius 6.1.25), but the root cause was **not** asm-offset misexecution — it was a cyrius-6.1.x `ud2` emitted for an *unresolved* `thread_local_*` call from sigil's `cbank` crypto cache (phylax hadn't declared the `thread_local` stdlib module; stdlib is opt-in). Declaring `thread_local` resolved the symbol and the test passes with correct digests. Matches sigil's own CHANGELOG 3.7.8 ("unresolved call to a `ud2`, not an asm misexecution"). No roll-back; the asm-offset path was never at fault for phylax's SHA-NI surface.

---

## Forward doc-policy commitments

| # | Commitment | Trigger | Source | Notes |
|---|---|---|---|---|
| 1 | **Audit retention** — `docs/audit/<date>-…md` files stay verbatim. The next audit pass gets its own date-stamped file; old ones never rewrite in place. | Each audit pass | This file | Today the surface is 1 file (the 2026-04-16 pre-1.1.0 pass). |
| 2 | **Bug filing retention** — `docs/bugs/<id>.md` + `docs/bugs/<id>-response.md` pairs stay frozen. If the same bug class resurfaces under a new toolchain, file a *new* dated pair rather than appending. | When a new cyrius-side bug bites phylax workloads | This file | Pattern keeps the historical record clean. |
| 3 | **Issue catalogue tracking** — `docs/development/issues/<date>-…md` files are walk-through-and-mark-closed when the underlying toolchain or dep moves past them, *but the file stays in place* (status flips inline). Don't delete; the file is the historical record of what was once broken and when. | At each toolchain bump | This file | Today the surface is 1 file (2026-04-30 cyrius-stdlib gaps). |
| 4 | **Open ADR / standards tiers only on a real trigger.** Don't add empty `docs/adr/` or `docs/standards/` directories — they'll degrade into checklist noise without a forcing function. | When a reversible-but-load-bearing decision earns an ADR, or a consumer asks for a structured conformance artifact | This file | Mirrors the majra / libro stance on the same tiers. |

---

## Refresh procedure

When docs are touched:

1. Find the affected row in the relevant tier table.
2. Update **Last touched** column to the new date.
3. Update **Status** column if the bucket changed.
4. Update **Notes** column if the next step changed.
5. If a doc moved or was archived, update its row to reflect the new home.
6. Re-anchor "Last refresh" date in the header.

When the bucket counts at the top drift by more than ~2 in any cell, refresh the at-a-glance table.

This file's refresh cadence is **opportunistic** (touched when other docs are touched), not periodic and not tied to releases. The 2026-05-11 toolchain + dep sweep established the baseline; future minor cuts' doc-sync step touches this file alongside CHANGELOG + roadmap when something here actually drifts.

---

## What this file is NOT

- Not a substitute for [`development/dependency-watch.md`](development/dependency-watch.md) (which holds live cyrius / sakshi / sigil / majra / bote version-tracking state).
- Not a CHANGELOG (which records what shipped, not what's stale).
- Not a roadmap (forward work lives in [`development/roadmap.md`](development/roadmap.md)).
- Not a per-doc review log (we record the result of an audit pass, not the per-doc reasoning).
