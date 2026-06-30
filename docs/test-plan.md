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
- K2 eBPF instruction/codegen smoke tests against the system Z3 library
- K2 raw equivalence wrapper smoke tests
- `ebpf-tv check --equiv-backend k2` ELF-section integration tests

The optional PREVAIL gate is:

```bash
make test-prevail-smoke
```

It clones a pinned upstream PREVAIL checkout, applies the local CMake
compatibility patch documented in `docs/reproduction-notes.md`, builds
`prevail` and `run_yaml`, and runs selected YAML and object smoke tests. It is
available as a manual GitHub Actions workflow because it depends on network
access and upstream build stability.

## Coverage Matrix

| Layer | Test entrypoint | What it proves | Current cases |
| --- | --- | --- | --- |
| CLI orchestration | `tests/test_cli.py` | `ebpf-tv` combines backend results as `FAIL > UNKNOWN > PASS` | identity pass, non-identical unknown, PREVAIL reject, missing PREVAIL, external fail |
| K2 backend contract | `tests/k2_equiv_smoke.py` via CTest | `k2_ebpf_equiv` returns normalized exit codes and JSON | byte-identical pass, return-value fail, stack store/load equivalent pass |
| K2 instruction semantics | vendored `k2_ebpf_inst_codegen_test` via CTest | selected K2 eBPF instruction, memory, map-helper, map-equivalence, and packet formulas still build and run against modern system Z3 | inherited K2 smoke cases |
| ELF adapter | `tests/k2_cli_integration.py` via CTest | `ebpf-tv` extracts ELF sections, generates default K2 metadata, and invokes K2 through the single CLI | byte-identical pass, ALU rewrite pass, stack-memory rewrite pass, return-value fail |
| CI | `.github/workflows/ci.yml` | fresh Ubuntu build installs dependencies and runs the same local gate | Python 3, clang/llvm, CMake, libz3-dev |
| Optional PREVAIL smoke | `make test-prevail-smoke`, `.github/workflows/prevail-smoke.yml` | real PREVAIL build and sample fixtures still work at the pinned commit | `add.yaml`, `map.yaml`, `minimal.bpf.o` |

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

The first checks adapter plumbing. The second checks non-identical ALU
equivalence. The third checks stack-memory modeling. These are intentionally
small fixtures because they must remain stable across hosts and solver versions.

## Current Negative Fixtures

The K2 equivalence path currently has CI coverage for:

- `r0 = 0; exit` versus `r0 = 1; exit`

This must return `FAIL`, not `UNKNOWN`, because the backend should produce a
semantic counterexample for this supported slice.

## PREVAIL Coverage

CI currently tests the PREVAIL adapter contract with fake PREVAIL commands:

- output containing `PASS:` is treated as `PASS`
- verifier/unmarshalling rejection text is treated as `FAIL`
- a missing PREVAIL binary is treated as `UNKNOWN`

Actual PREVAIL build and sample-object reproduction are covered by the optional
`make test-prevail-smoke` target and manual `PREVAIL Smoke` workflow. This is a
reproducibility gate for PREVAIL integration, not part of the default CI gate.
End-to-end safety coverage still requires wiring real PREVAIL results into
regular old/new object checks.

## Missing Coverage

The following are intentionally not claimed yet:

- automatic map metadata extraction from ELF/BTF
- CO-RE relocation modeling
- helper side effects beyond K2's inherited smoke tests
- map update/delete equivalence through `ebpf-tv check`
- packet/context memory equivalence through `ebpf-tv check`
- mutable global equivalence
- ringbuf/perf-event output sink tracking
- atomicity-preservation structural checks
- program-type/context compatibility checks before equivalence
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
