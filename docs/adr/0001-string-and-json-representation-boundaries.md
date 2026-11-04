# ADR 0001 — String and JSON representation boundaries

- **Status**: Accepted
- **Date**: 2026-08-23 (amended 2026-11-04, 1.3.1 — lookup keys, third-party payloads)
- **Context**: the 1.2.5 crash-fix pass (four SIGSEGV'ing CLI paths, plus the
  same defect latent in `quarantine.cyr` and `integration.cyr`)

## Context

Cyrius carries two string representations and phylax uses both:

| | Layout | Length | Produced by |
|---|---|---|---|
| **cstr** | `char*`, NUL-terminated | `strlen(p)` — a scan | `argv(i)`, bare `"literals"` |
| **Str** | 16-byte header `{data: ptr, len: i64}` | `str_len(s)` — `load64(s + 8)` | `str_from`, `str_new`, `str_cat`, `path_join`, `str_split` |

Neither is tagged at runtime, and phylax's own functions are declared without
type annotations (`fn cmd_report(path, format, rules_path)`), so nothing checks
the handoff. Passing a cstr where a `Str` is expected reads *the eight bytes
after the NUL* as a length. That is not a null dereference with a tidy crash —
it is a plausible-looking large integer, so the failure is a wild read whose
outcome depends on what happens to sit past the string in memory. `phylax bogus`
printed an empty name; `phylax "scan /tmp/pl"` segfaulted. Same bug, same line.

The same shape of mistake existed one level up, in JSON. `bayan` exposes two
unrelated builders:

- `json_build(pairs)` — takes a `Vec` of 16-byte `{key: Str, value: Str}`
  pairs and emits a flat `{"k":"v", ...}` object. No nesting, no numbers, no
  booleans, no escaping.
- `json_v_*` — a tagged value tree (`JTAG_NULL/BOOL/INT/FLOAT/STR/ARR/OBJ`)
  with `json_v_build` for serialization.

A HashMap is neither. Handing `json_build` a map makes it read the map header's
`cap` field (offset 8) as a vec length and walk the 24-byte entry array on an
8-byte stride, dereferencing empty slots as pair pointers. Five call sites did
exactly this and every one of them was an unconditional SIGSEGV, including both
of `phylax report`'s machine-readable output formats.

None of it was caught because the affected functions had no tests, or — in
`report_render_markdown`'s case — a test that only covered the single input
shape (an empty report) that happened not to trip the bug.

## Decision

**1. Structs hold `Str`. Argv holds cstr. Convert at the boundary, explicitly.**

Any field documented as a string in a phylax struct is a `Str`, including
`ScanTarget.data` (0 for `SCAN_TARGET_MEMORY`), `ThreatFinding.rule_name` /
`.description`, `ThreatReport.session_id` / `.generated_at`, and every
`QuarantineEntry` path.

Values obtained from `argv` stay cstrs and are named as such in the function's
doc comment. They convert with `str_from(p)` at the first `Str`-consuming call,
and `Str`s convert with `str_to_cstr(s)` at the first syscall. There is no
"either works here" position — a function takes one or the other, and its
comment says which.

Consequences worth stating: `strlen` is for cstrs and `str_len` is for `Str`s,
never the reverse; a defaulted option must be built in the *same*
representation as the parsed one (`--hoosh-url` defaulted to a `Str` and parsed
to a cstr, then got `str_len`'d); and `phylax_read_file` returns `0`, not an
empty `Str`, on failure, so its result is checked for `0` before any `str_len`.

**2. JSON is built with `json_v_*`. `json_build` is not used in phylax.**

Every document phylax emits or consumes — the JSON report, SARIF, the
quarantine index, Hoosh/Daimon request bodies — nests, carries integers, or
both. `json_v_*` is the only builder that can express them, and it escapes
strings at serialization time, which `json_build` does not do at all. Parsing
follows the same rule: `json_v_parse` returns a tree that `json_v_obj_get`
walks; `json_parse` returns a flat pair `Vec` that must never be handed to
`map_get`.

**3. A renderer's test asserts on parsed output, not on length.**

`assert(str_len(out) > 0)` passes for output no parser accepts. Renderer tests
parse their own output back with `json_v_parse` and check the tag of each
value, so "the count came out as a string" and "the nesting collapsed" are
failures rather than green.

### Amendment (1.3.1) — lookup KEYS have a representation too

The boundary above covered values and paths. It also applies to the key a
lookup compares against, and there the failure is silent rather than a crash.
bayan's bare legacy lookups disagree with each other: `toml_get` /
`toml_get_sections` compare a **cstr** key (`str_eq_cstr`), while `json_get`
compares a **Str** key (`str_eq`). Each answers the other's type with "not
found". bayan 1.11.1 (its ADR 0014) adds typed `_by_cstr` / `_by_str` variants
and `#deprecated` the bare names, and cyrius 6.7.18 then flags a Str passed
where a cstring is declared. That surfaced three phylax defects that predate it:
every `toml_get(pairs, str_from("…"))` in the YARA TOML loader and in
`load_config` had never matched, and `phylax_scan_handler` crashed (see below).

**Decision:** phylax calls the typed lookups only:
`bayan_toml_get_by_cstr` / `bayan_toml_get_sections_by_cstr` /
`bayan_json_get_by_cstr` / `bayan_json_v_obj_get_by_cstr` with a literal key,
or the `_by_str` form with a Str. It never calls the bare aliases.

**Third-party payloads are a boundary as well.** bote's dispatcher hands an MCP
tool handler the tools/call `arguments` as raw JSON **text** (a cstr), not
parsed pairs. `phylax_scan_handler` passed that text to `json_get`, which read
it as a Vec header and killed the process on the first call (SIGSEGV, measured
on 1.3.0). A handler parses its arguments itself (`bayan_json_v_parse_buf`) and
returns a JSON **cstr**. The registration side had the same mismatch:
`phylax_register_tools` passed Str names, descriptions and schemas, so bote
refused every tool (`registry_len` 0), and an inputSchema turned out to be a
bote ToolSchema object rather than JSON text (`tool_schema_from_json`).
Each case is pinned by a test that fails on the old code: `yara_toml_rules`,
`config_toml`, `mcp_scan_handler` and `mcp_bote_e2e`, which sends real JSON-RPC
through bote's codec and dispatcher.

## Alternatives considered

- **Annotate phylax's functions with `Str` / `cstring` types** so the compiler
  checks the handoff. This is the real fix and the direction to move in, but it
  is a whole-tree change across 8,700 lines and several of these functions are
  legitimately polymorphic today. Recorded here as the intended follow-up; the
  convention above is what holds the line until then.
- **Normalize everything to `Str` at `main()` and never touch a cstr.** Cheaper
  to reason about, but the syscall wrappers, `streq`, and the whole
  `arg_find_option` / `arg_collect_positional` surface are cstr-native, so this
  trades one conversion boundary for another and adds an allocation per
  argument.
- **Keep `json_build` for the flat documents.** Nothing phylax emits is
  actually flat, and having two builders in the tree is what produced the bug
  in the first place.

## Consequences

- Consumers constructing a `ScanTarget` must pass `str_from(path)` rather than
  a bare literal. `tests/test_integration.tcyr` was updated for this and pins
  the contract with an assertion.
- The quarantine index on disk is now a JSON array of objects with `size` and
  `timestamp` as numbers. No migration is needed: the previous code never
  successfully wrote an index, so there is no old format in the field.
- `tests/test_cli.tcyr` exists so the argv boundary is reachable from a test at
  all — it is the one test file that includes `src/cli.cyr`.
