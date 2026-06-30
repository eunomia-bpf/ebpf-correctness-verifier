# eBPF Correctness Verifier

Research prototype and design notes for validating eBPF program
transformations proposed by untrusted optimizers or agents.

The core premise is:

```text
untrusted agent / optimizer / migration tool
        |
        v
candidate eBPF source or bytecode
        |
        v
kernel verifier safety gate
        |
        v
bytecode-level equivalence or refinement checker
        |
        v
benchmark and regression gate
```

The Linux kernel verifier is necessary but not sufficient. It can reject unsafe
programs, but it does not prove that a transformed program preserves the
observable behavior of the original program.

## Current Recommendation

The first implementation should not be a from-scratch symbolic executor. The
better strategy is to build a reproduction and adapter harness around existing
analyzers:

- [`vbpf/prevail`](https://github.com/vbpf/prevail) as the default safety,
  CFG, abstract-interpretation, and invariant baseline.
- [`smartnic/superopt`](https://github.com/smartnic/superopt), the K2 code base,
  as the closest available eBPF equivalence-checking reference and test source.
- [`dslab-epfl/ebpf-se`](https://github.com/dslab-epfl/ebpf-se) as a KLEE-based
  symbolic-execution baseline for selected examples, preferably containerized.
- kernel verifier and `BPF_PROG_RUN` as the target-kernel compatibility and
  concrete replay gates.

PREVAIL is a better first substrate than implementing verifier-like abstract
interpretation or CFG reasoning ourselves. K2 still matters because PREVAIL is a
safety verifier, not an old/new semantic equivalence checker. The project should
therefore be an adapter-plus-comparison harness first, and only implement small
missing glue where no reusable tool exists.

The recommended MVP is:

1. Reproduce representative PREVAIL, K2, and eBPF-SE examples.
2. Add a small local harness that records analyzer commands and expected results.
3. Use PREVAIL as the first safety/invariant gate.
4. Use K2 tests and semantics to evaluate equivalence-checking coverage.
5. Add kernel verifier and `BPF_PROG_RUN` gates for concrete validation.
6. Add a strict `PASS` / `FAIL` / `UNKNOWN` result model across all gates.

## Documents

- [Research survey](docs/research-survey.md)
- [Reuse matrix](docs/reuse-matrix.md)
- [MVP architecture](docs/mvp-architecture.md)
- [Reproduction notes](docs/reproduction-notes.md)

## Status

This repository currently contains the initial research and implementation plan.
It intentionally does not include CI, packaging, or a heavy dependency stack yet.
