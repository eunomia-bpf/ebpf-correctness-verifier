# eBPF Correctness Verifier

`ebpf-tv` is a thin userspace translation-validation frontend for eBPF program
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

## Quick Start

Run the Python CLI tests:

```bash
make test-python
```

Build and run the vendored K2 eBPF semantics smoke test against the system Z3:

```bash
make test-k2-smoke
```

Run the CLI with an already-built PREVAIL binary:

```bash
PYTHONPATH=src python3 -m ebpf_tv check old.bpf.o new.bpf.o \
  --section xdp \
  --prevail-bin /path/to/prevail
```

The CLI returns JSON by default:

```json
{
  "result": "UNKNOWN",
  "stages": [
    {
      "name": "prevail_old",
      "result": "PASS",
      "reason": "prevail_pass"
    },
    {
      "name": "prevail_new",
      "result": "PASS",
      "reason": "prevail_pass"
    },
    {
      "name": "equivalence",
      "result": "UNKNOWN",
      "reason": "non_identical_requires_equivalence_backend"
    }
  ]
}
```

## Current Design

The implementation is deliberately not a from-scratch symbolic executor. The
maintainable path is to keep the project as a small frontend over existing
analyzers and a vendored K2-derived equivalence core:

- PREVAIL is the safety, CFG, abstract-interpretation, and invariant backend.
- Vendored K2/superopt is the eBPF equivalence-semantics source.
- `ebpf-tv` owns the CLI, tri-state result schema, backend contracts, tests, and
  modern build overlay.

K2 is vendored under `third_party/k2-superopt` with its original MIT license and
provenance notes. The root CMake build compiles a K2 eBPF instruction/codegen
smoke test against the system Z3 library, avoiding K2's old requirement for a
sibling `../z3/build/config.mk` checkout.

The v0 rule is:

```text
PASS =
  PREVAIL(old) PASS
  AND PREVAIL(new) PASS
  AND equivalence(old, new) PASS
```

The default equivalence backend is intentionally conservative: byte-identical
objects pass, non-identical objects return `UNKNOWN` unless an external
equivalence backend is configured. This keeps the public CLI honest while the
K2-derived old/new equivalence CLI is extracted.

## Documents

- [Research survey](docs/research-survey.md)
- [Reuse matrix](docs/reuse-matrix.md)
- [MVP architecture](docs/mvp-architecture.md)
- [Backend contract](docs/backend-contract.md)
- [Reproduction notes](docs/reproduction-notes.md)

## Status

This repository now contains a first runnable `ebpf-tv` CLI, a PREVAIL backend
adapter, a conservative equivalence backend contract, vendored K2 source, and a
modern-Z3 K2 smoke target. It is not yet a complete old/new eBPF equivalence
checker.
