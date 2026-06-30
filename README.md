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

The best immediate reuse target is
[`smartnic/superopt`](https://github.com/smartnic/superopt), the public K2 code
base. It already contains an eBPF ISA formalization, a Z3-backed equivalence
checking path, stochastic search, and eBPF-specific verification structure.

Do not treat K2 as a turnkey production validator. Treat it as the closest
available semantic-checking reference implementation and source of reusable
ideas/tests. For a maintained eunomia-bpf project, the stronger long-term path
is a clean validator library built around modern eBPF object tooling:

- Rust path: `aya-obj` / Aya + Z3 bindings + custom eBPF symbolic executor.
- Go path: `cilium/ebpf` + `cilium/ebpf/asm` + Z3 or SMT-LIB emission.

The recommended MVP is:

1. Reproduce a small K2 equivalence-checking example.
2. Build a standalone bytecode parser and normalizer.
3. Support helper-free ALU, branch, stack, and packet-read equivalence.
4. Add a strict `PASS` / `FAIL` / `UNKNOWN` result model.
5. Add kernel verifier and `BPF_PROG_RUN` gates for concrete validation.

## Documents

- [Research survey](docs/research-survey.md)
- [Reuse matrix](docs/reuse-matrix.md)
- [MVP architecture](docs/mvp-architecture.md)

## Status

This repository currently contains the initial research and implementation plan.
It intentionally does not include CI, packaging, or a heavy dependency stack yet.
