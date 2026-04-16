# Contributing to Phylax

Thank you for considering contributing to Phylax. This guide will help you get started.

## Prerequisites

- Cyrius 5.1.3+ (see `.cyrius-toolchain`)
- The Cyrius build tool (`cyrius build`, `cyrius test`, `cyrius bench`)

## Getting started

```bash
git clone https://github.com/MacCracken/phylax
cd phylax
cyrius deps                          # resolve dependencies
cyrius build src/main.cyr build/phylax  # build
cyrius test tests/phylax.tcyr        # run tests
```

## Development workflow

| Command | What it does |
|---------|-------------|
| `cyrius build src/main.cyr build/phylax` | Build the binary |
| `cyrius test tests/phylax.tcyr` | Run all tests |
| `cyrius bench tests/phylax.bcyr` | Run 12 benchmark groups |
| `cyrius check src/main.cyr` | Syntax check |
| `cyrius fmt src/main.cyr` | Format code |
| `cyrius lint src/main.cyr` | Static analysis |
| `cyrius vet src/main.cyr` | Include verification |
| `cyrius deny src/main.cyr` | Policy enforcement |
| `./scripts/bench-history.sh` | CSV + 3-run Markdown tracking |

## What to contribute

- Bug fixes with regression tests
- New analysis modules (binary format parsers, heuristic detectors)
- YARA rule improvements (new pattern types, condition operators)
- Documentation improvements and examples
- Integration tests and fuzz targets
- Benchmark improvements

## Code style

- `cyrius fmt` — required, checked in CI
- `cyrius lint` — zero warnings
- Bounds check all buffer access (`offset < data_len` before `load8/16/32/64`)
- No raw `syscall` without input validation
- Use `sakshi_info/warn/error` for logging, not `println` in library functions
- Comment section headers with `# ================================================================`
- Keep functions focused — one responsibility per function

## Project layout

```
src/main.cyr           — Complete engine (single flat binary)
tests/phylax.tcyr      — Test suite (16 test groups)
tests/phylax.bcyr      — Benchmarks (12 groups)
tests/phylax.fcyr      — Fuzz harness
scripts/               — Build and benchmark scripts
docs/                  — Architecture, roadmap, guides
```

## Adding a new analyzer

1. Add analysis functions to `src/main.cyr` in the appropriate section
2. Return findings via `vec_push` into a findings vec
3. Add unit tests in `tests/phylax.tcyr` as a new `test_group`
4. Wire it into the `run_scan()` pipeline near the bottom of `main.cyr`
5. Add a fuzz target if the analyzer processes untrusted input
6. Add benchmarks in `tests/phylax.bcyr`

## Commit messages

- Use imperative mood: "add PE header parser" not "added PE header parser"
- Keep subject under 72 characters
- Reference issues where applicable: "fix #42: handle truncated ELF headers"

## Pull requests

- One logical change per PR
- Include tests for new functionality
- Update docs if the public API changes
- All CI checks must pass (fmt, lint, test, vet, deny)

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0.
