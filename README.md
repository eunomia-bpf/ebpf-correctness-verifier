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

Run the full local test suite:

```bash
make test
```

Run only the Python CLI tests:

```bash
make test-python
```

Build and run the vendored K2 eBPF semantics smoke test against the system Z3:

```bash
make test-k2-smoke
```

Run the K2-derived raw-instruction equivalence backend directly:

```bash
build/k2_ebpf_equiv \
  --old old.ins \
  --new new.ins \
  --map program.maps \
  --desc program.desc \
  --k2-root third_party/k2-superopt
```

Or run both K2 smoke checks through the Python frontend:

```bash
PYTHONPATH=src python3 -m ebpf_tv selftest \
  --k2-inst-codegen-test build/k2_ebpf_inst_codegen_test \
  --k2-equiv build/k2_ebpf_equiv \
  --k2-root third_party/k2-superopt
```

Run the CLI with an already-built PREVAIL binary:

```bash
PYTHONPATH=src python3 -m ebpf_tv check old.bpf.o new.bpf.o \
  --section xdp \
  --prevail-bin /path/to/prevail
```

Run the full v0 gate with PREVAIL and the K2 backend:

```bash
PYTHONPATH=src python3 -m ebpf_tv check old.bpf.o new.bpf.o \
  --section xdp \
  --prevail-bin /path/to/prevail \
  --equiv-backend k2 \
  --k2-equiv build/k2_ebpf_equiv \
  --k2-root third_party/k2-superopt
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
smoke test and a K2-derived raw-instruction equivalence backend against the
system Z3 library, avoiding K2's old requirement for a sibling
`../z3/build/config.mk` checkout.

The v0 rule is:

```text
PASS =
  PREVAIL(old) PASS
  AND PREVAIL(new) PASS
  AND equivalence(old, new) PASS
```

The default equivalence backend is intentionally conservative: byte-identical
objects pass, non-identical objects return `UNKNOWN` unless an external
equivalence backend is configured. The vendored K2 backend can be selected with
`--equiv-backend k2`; `ebpf-tv` extracts the requested ELF section with
`llvm-objcopy`/`objcopy`, then calls the K2 raw-instruction checker with
generated no-map constant-input metadata or user-supplied `.maps` and `.desc`
metadata.

## Documents

- [Research survey](docs/research-survey.md)
- [Reuse matrix](docs/reuse-matrix.md)
- [MVP architecture](docs/mvp-architecture.md)
- [Backend contract](docs/backend-contract.md)
- [Reproduction notes](docs/reproduction-notes.md)

## CI

GitHub Actions runs `make test` on Ubuntu 24.04 with system `libz3-dev`,
`clang`, `llvm`, and CMake. The CI suite covers the Python frontend, K2
instruction semantics, the K2 raw equivalence wrapper, and the `ebpf-tv check
--equiv-backend k2` ELF-section integration smoke test. The integration fixture
checks byte-identical objects, non-identical equivalent rewrites
(`r0 = 1` versus `r0 = 0; r0 += 1`, and direct register return versus
stack store/load), and a return-value counterexample.

## Status

This repository now contains a first runnable `ebpf-tv` CLI, a PREVAIL backend
adapter, a conservative equivalence backend contract, vendored K2 source, and a
modern-Z3 K2 equivalence backend with unit tests and an ELF-section integration
smoke test. It is not yet a complete CO-RE/BTF-aware object equivalence checker.
