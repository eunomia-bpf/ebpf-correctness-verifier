# Test Plan

This project is a translation-validation frontend, so tests must prove both
the orchestration contract and the reused backend wiring. Passing tests do not
mean arbitrary eBPF transformations are proven correct; they mean the supported
slice returns conservative `PASS`, `FAIL`, or `UNKNOWN` results through the
documented pipeline.

## Required Local Gate

```bash
make test
```

`make test` is the same command used by GitHub Actions. It runs:

- Python CLI unit tests
- package installation and `ebpf-tv` console-script smoke tests in a temporary
  virtual environment
- K2 eBPF instruction/codegen smoke tests against the system Z3 library
- K2 raw equivalence wrapper smoke tests
- `ebpf-tv check --equiv-backend k2` ELF-section integration tests
- the public K2 XDP CLI example under `examples/k2-xdp`

The optional PREVAIL gate is:

```bash
make test-prevail-smoke
```

It clones a pinned upstream PREVAIL checkout, applies the local CLI
compatibility patch documented in `docs/reproduction-notes.md`, builds
`prevail` and `run_yaml`, runs selected YAML and object smoke tests, and then
runs `ebpf-tv check` against PREVAIL's minimal object fixture with the real
PREVAIL binary. It is available as a manual GitHub Actions workflow because it
depends on network access and upstream build stability.

The upstream Z3 compatibility gate is:

```bash
make test-k2-z3-release
```

It downloads the pinned official Z3 release zip, verifies its sha256, rebuilds
the K2 targets against that release's headers and shared library, runs the K2
CTest suite, and checks `k2_ebpf_equiv --version`. GitHub Actions runs this as
a separate job so the default local `make test` gate stays network-free.

## Coverage Matrix

| Layer | Test entrypoint | What it proves | Current cases |
| --- | --- | --- | --- |
| CLI orchestration | `tests/test_cli.py` | `ebpf-tv` combines backend results as `FAIL > UNKNOWN > PASS` | identity pass, non-identical unknown, PREVAIL reject, missing PREVAIL, external fail |
| Capability contract | `tests/test_cli.py` | `ebpf-tv capabilities` exposes the dependency policy, supported K2 slice, and known gaps as a stable CLI surface | JSON dependency policy, K2 legacy-map, BTF guard, and XDP-desc features, BTF/CO-RE gaps, text output |
| Package smoke | `make test-package` | the project installs from `pyproject.toml` and exposes the `ebpf-tv` console script | top-level help, `check --help`, and `capabilities` |
| K2 backend contract | `tests/k2_equiv_smoke.py` via CTest | `k2_ebpf_equiv` returns normalized exit codes, JSON, and backend provenance | `--version` K2/Z3 report, byte-identical pass, return-value fail, stack store/load equivalent pass, map update/lookup pass/fail, packet read pass/fail |
| K2 instruction semantics | vendored `k2_ebpf_inst_codegen_test` via CTest | selected K2 eBPF instruction, memory, map-helper, map-equivalence, and packet formulas still build and run against modern system Z3 | inherited K2 smoke cases |
| Upstream Z3 release | `make test-k2-z3-release`, CI `upstream-z3` job | the vendored K2 wrapper builds and runs against the pinned official Z3 release, not only distro `libz3-dev` | sha256-verified Z3 4.16.0 binary release, K2 CTest suite, wrapper version JSON |
| ELF adapter | `tests/k2_cli_integration.py` via CTest | `ebpf-tv` extracts ELF sections, generates default, section-inferred, auto-extracted legacy, or explicit K2 metadata, and invokes K2 through the single CLI | byte-identical pass, ALU rewrite pass, stack-memory rewrite pass, map update/lookup pass/fail with explicit map metadata, map rewrite pass with auto-extracted legacy map metadata, XDP packet-input inference, packet read pass/fail with explicit packet metadata, return-value fail |
| Section metadata precheck | `tests/test_cli.py` | explicit old/new section overrides route PREVAIL/K2 to the right ELF sections and reject known incompatible program types before solving | external backend old/new section placeholders, compatible XDP section override pass, XDP-vs-tracepoint mismatch returns `FAIL`, unclassified section mismatch returns `UNKNOWN` before K2 is invoked |
| BTF metadata guard | `tests/test_cli.py`, `tests/k2_cli_integration.py` via CTest | K2 auto-generated map environments do not silently ignore modern BTF-only map metadata | fake objcopy unit coverage plus clang-produced `.BTF` object returns `UNKNOWN` before K2 is invoked |
| K2 metadata precheck | `tests/test_cli.py` | explicit old/new K2 program descriptions are checked before equivalence solving | byte-identical `--k2-old-desc`/`--k2-new-desc` continues to K2, mismatch returns `FAIL` before K2 is invoked |
| Public examples | `make test-example-k2-xdp` | documented CLI examples remain runnable through the same tested K2 backend | non-identical equivalent XDP objects with fake PREVAIL and K2 equivalence PASS |
| CI | `.github/workflows/ci.yml` | fresh Ubuntu build installs dependencies and runs the same local gate | Python 3 packaging tools, clang/llvm, CMake, libz3-dev |
| Optional PREVAIL smoke | `make test-prevail-smoke`, `.github/workflows/prevail-smoke.yml` | real PREVAIL build, sample fixtures, and `ebpf-tv check` integration still work at the pinned commit | `add.yaml`, `map.yaml`, direct `minimal.bpf.o` PREVAIL pass, `ebpf-tv check minimal.bpf.o minimal.bpf.o` PASS |

## Heimdall-Derived Acceptance Lessons

The Heimdall paper is relevant because it measures the gap between compiling,
kernel-verifier acceptance, safety policy, and bytecode equivalence. Its results
support this project's default rule: a verifier pass is only an input to the
gate, not a transformation-correctness proof.

As backend support grows, add fixtures in this order:

- map lookup/update/delete with symbolic keys and last-write-wins behavior
- mutable globals paired with map state
- output sinks in both default sink mode and strict byte-comparison mode
- entry-point/program-type mismatch as a pre-symbolic-execution rejection
- dropped atomic operation as a structural `FAIL`
- helper-failure modeling that returns `UNKNOWN` when the backend cannot prove
  both programs use the same helper outcome model

## Current Positive Fixtures

The K2 equivalence path currently has CI coverage for:

- `r0 = 0; exit` versus itself
- `r0 = 1; exit` versus `r0 = 0; r0 += 1; exit`
- `r0 = r1; exit` versus `*(u32 *)(r10 - 4) = r1; r0 = *(u32 *)(r10 - 4); exit`
- `map_update(k, r1); r0 = *map_lookup(k); exit` versus returning the same
  stack value used for the update
- the same map rewrite through `ebpf-tv check` with K2 metadata generated from a
  legacy ELF `maps` section
- XDP sections without `--k2-desc` generate K2 packet-input metadata with a
  bounded default packet size
- packet byte read at offset 0 versus itself under packet-input metadata

The first checks adapter plumbing. The second checks non-identical ALU
equivalence. The third checks stack-memory modeling. The map and packet fixtures
exercise K2 metadata parsing, the helper/memory models, and the `ebpf-tv check`
ELF-section frontend path. These are intentionally small fixtures because they
must remain stable across hosts and solver versions.

## Current Negative Fixtures

The K2 equivalence path currently has CI coverage for:

- `r0 = 0; exit` versus `r0 = 1; exit`
- section-inferred XDP versus tracepoint program-type mismatch before K2 is
  invoked
- map update followed by lookup versus lookup-only
- old/new legacy map metadata mismatch before K2 is invoked
- old/new explicit K2 program-description metadata mismatch before K2 is invoked
- packet byte read at offset 0 versus offset 1

This must return `FAIL`, not `UNKNOWN`, because the backend should produce a
semantic counterexample for each supported slice.

## Current Conservative UNKNOWN Fixtures

The K2 frontend currently has CI coverage for:

- no legacy `maps` section plus present `.BTF` metadata returns `UNKNOWN` before
  K2 is invoked, including a clang-produced BTF object in the ELF integration
  test

This prevents the auto-generated empty-map environment from claiming support for
modern libbpf/BTF map metadata before a real extractor exists.

## PREVAIL Coverage

CI currently tests the PREVAIL adapter contract with fake PREVAIL commands:

- output containing `PASS:` is treated as `PASS`
- verifier/unmarshalling rejection text is treated as `FAIL`
- a missing PREVAIL binary is treated as `UNKNOWN`

Actual PREVAIL build and sample-object reproduction are covered by the optional
`make test-prevail-smoke` target and manual `PREVAIL Smoke` workflow. This is a
reproducibility gate for PREVAIL integration, not part of the default CI gate.
The optional gate also runs `ebpf-tv check` on the same minimal object as both
old and new input, so the project-owned PREVAIL adapter is exercised against
real PREVAIL output instead of only fake unit-test commands.

## Missing Coverage

The following are intentionally not claimed yet:

- modern BTF `.maps` metadata extraction; only a presence guard exists today
- BTF/loader-derived program description extraction beyond section-prefix
  inference
- CO-RE relocation modeling
- helper side effects beyond K2's inherited smoke tests
- map delete equivalence through `ebpf-tv check`
- broader packet/context memory equivalence through `ebpf-tv check`
- mutable global equivalence
- ringbuf/perf-event output sink tracking
- atomicity-preservation structural checks
- automatic program-type/context compatibility extraction from loader or BTF
  metadata beyond the small section-prefix table before equivalence
- target-kernel verifier loading
- `BPF_PROG_RUN` replay or differential execution
- agent-facing counterexample minimization

Unsupported or unmodeled cases must return `UNKNOWN` instead of `PASS`.

## Adding New Fixtures

New equivalence fixtures should satisfy these rules:

- keep old/new programs minimal and readable
- include at least one non-identical `PASS` case for each new semantic feature
- include at least one supported `FAIL` case when the feature admits a small
  counterexample
- keep host dependencies limited to the CI dependency set unless the workflow is
  explicitly expanded
- document whether the fixture validates raw K2 behavior, ELF extraction, CLI
  orchestration, or a combination of those layers
