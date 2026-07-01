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

Install the CLI in a local virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
ebpf-tv --help
```

Inspect the currently supported dependency policy, backend slice, and known
gaps:

```bash
ebpf-tv capabilities
```

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

Build and run the same K2 smoke test against the pinned upstream Z3 release
used by CI:

```bash
make test-k2-z3-release
```

Run the CI-covered K2 XDP CLI example:

```bash
make test-example-k2-xdp
```

Run the K2-derived raw-instruction equivalence backend directly:

```bash
build/k2_ebpf_equiv --version

build/k2_ebpf_equiv \
  --old old.ins \
  --new new.ins \
  --map program.maps \
  --desc program.desc \
  --k2-root third_party/k2-superopt
```

Or run both K2 smoke checks through the Python frontend:

```bash
ebpf-tv selftest \
  --k2-inst-codegen-test build/k2_ebpf_inst_codegen_test \
  --k2-equiv build/k2_ebpf_equiv \
  --k2-root third_party/k2-superopt
```

Run the CLI with an already-built PREVAIL binary:

```bash
ebpf-tv check old.bpf.o new.bpf.o \
  --section xdp \
  --prevail-bin /path/to/prevail
```

Run the full v0 gate with PREVAIL and the K2 backend:

```bash
ebpf-tv check old.bpf.o new.bpf.o \
  --section xdp \
  --prevail-bin /path/to/prevail \
  --equiv-backend k2 \
  --k2-equiv build/k2_ebpf_equiv \
  --k2-root third_party/k2-superopt
```

Run the optional real PREVAIL smoke against a pinned upstream checkout:

```bash
make test-prevail-smoke
```

This clones `vbpf/prevail` outside the tracked source tree, applies a small
`PREVAIL_VERSION_STRING` CLI compatibility patch needed by current compilers,
builds `prevail` and `run_yaml`, runs YAML and object smoke tests, then runs
`ebpf-tv check` on PREVAIL's minimal object fixture with the real PREVAIL
binary. It is kept out of the default `make test` gate because it depends on
network access and upstream build behavior.

For source-tree development without installing the package, use
`PYTHONPATH=src python3 -m ebpf_tv ...`.

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

## Diagnostics

Use `ebpf-tv doctor` to check local dependency wiring without running a
transformation proof:

```bash
ebpf-tv doctor \
  --prevail-bin /path/to/prevail \
  --k2-equiv build/k2_ebpf_equiv \
  --k2-root third_party/k2-superopt
```

The command reports PREVAIL, K2, Z3, K2 root, and objcopy readiness using the
same `PASS`/`UNKNOWN`/`FAIL` result model as `check`.

## System Dependencies

On Ubuntu 24.04, the default CI gate installs:

```bash
sudo apt-get install -y --no-install-recommends \
  clang \
  cmake \
  g++ \
  libz3-dev \
  llvm \
  python3 \
  python3-pip \
  python3-setuptools \
  python3-venv \
  python3-wheel
```

`make test-k2-z3-release` also needs `curl` and `unzip` to download and verify
the pinned upstream Z3 release. PREVAIL is optional for the default gate; use
`make test-prevail-smoke` when you need the real PREVAIL integration smoke.

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

Z3 and PREVAIL are intentionally not default submodules. Z3 is consumed as a
system solver library (`libz3-dev` in CI), while PREVAIL is consumed as an
external CLI through `--prevail-bin` with an optional pinned smoke workflow.
`ebpf-tv doctor` reports whether the configured local binaries and K2 root are
usable, and includes the K2 wrapper's Z3 version report when available.
See [Dependency policy](docs/dependency-policy.md) for the maintainer contract.

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
auto-extracted legacy `maps` metadata, section-inferred `.desc` metadata, or
user-supplied `.maps` and `.desc` metadata. The current section inference is
deliberately small: XDP sections default to K2 packet input with a bounded
64-byte packet size, and unknown sections default to constant input. When users
provide separate `--k2-old-desc` and `--k2-new-desc` metadata files, `ebpf-tv`
checks that the explicit program descriptions match before invoking K2. When
`--old-section` and `--new-section` differ, `ebpf-tv` also checks compatible
program types for known section prefixes such as XDP and tracepoints before
extracting bytecode. If automatic map extraction finds no legacy `maps` section
but detects `.BTF`, the K2 backend returns `UNKNOWN` instead of assuming an
empty map environment.

## Documents

- [K2 XDP example](examples/k2-xdp/README.md)
- [Dependency policy](docs/dependency-policy.md)
- [Research survey](docs/research-survey.md)
- [Reuse matrix](docs/reuse-matrix.md)
- [Heimdall notes](docs/heimdall-notes.md)
- [MVP architecture](docs/mvp-architecture.md)
- [Backend contract](docs/backend-contract.md)
- [Test plan](docs/test-plan.md)
- [Reproduction notes](docs/reproduction-notes.md)
- [Contributing](CONTRIBUTING.md)

## CI

GitHub Actions runs `make test` on Ubuntu 24.04 with system `libz3-dev`,
`clang`, `llvm`, and CMake, plus an independent `make test-k2-z3-release` job
against the pinned upstream Z3 release. The CI suite covers the Python
frontend, K2 instruction semantics, the K2 raw equivalence wrapper, and the
`ebpf-tv check --equiv-backend k2` ELF-section integration smoke test. The
integration fixture checks byte-identical objects, non-identical equivalent rewrites
(`r0 = 1` versus `r0 = 0; r0 += 1`, and direct register return versus
stack store/load), and a return-value counterexample. The raw K2 backend smoke
also covers explicit map metadata and packet-input metadata with supported
PASS/FAIL cases, and the ELF-section integration test covers those explicit
metadata paths plus automatic legacy `maps` extraction and XDP packet-desc
inference through `ebpf-tv check`, and verifies that a clang-produced `.BTF`
object returns `UNKNOWN` before K2 when no legacy map metadata is available. CI
also runs the K2 XDP example script so the public example path stays in sync
with the tested CLI behavior.

The optional `PREVAIL Smoke` workflow can be run manually from GitHub Actions to
verify the pinned real PREVAIL build and object/YAML fixtures.

## Status

This repository now contains a first runnable `ebpf-tv` CLI, a PREVAIL backend
adapter, a conservative equivalence backend contract, vendored K2 source, and a
modern-Z3 K2 equivalence backend with unit tests and an ELF-section integration
smoke test. It is not yet a complete CO-RE/BTF-aware object equivalence checker;
automatic map extraction currently supports only legacy `SEC("maps")`
`bpf_map_def` records, BTF-only map metadata is detected as unsupported, and
automatic `.desc` generation only handles a small section-prefix slice.
