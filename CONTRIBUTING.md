# Contributing

`ebpf-tv` is intentionally a small translation-validation frontend. Changes
should preserve that shape: reuse PREVAIL, K2, Z3, LLVM tools, or another
maintained backend where possible, and keep project-owned code focused on
orchestration, contracts, diagnostics, tests, and documentation.

## Development Setup

Install the Python package in editable mode:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

On Ubuntu 24.04, install the same host tools used by CI:

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

Build the K2-derived backend against the system Z3:

```bash
make test-k2-smoke
```

Inspect local dependency wiring:

```bash
ebpf-tv doctor \
  --prevail-bin /path/to/prevail \
  --k2-equiv build/k2_ebpf_equiv \
  --k2-root third_party/k2-superopt
```

## Design Rules

- Do not implement a new symbolic executor, abstract interpreter, verifier, or
  solver in this repository.
- Keep PREVAIL external by default. Use `--prevail-bin` and the optional
  `make test-prevail-smoke` gate for real PREVAIL coverage.
- Keep Z3 external by default. Use system `libz3-dev` plus
  `make test-k2-z3-release` for the pinned upstream release check.
- Vendor K2 only because this repository maintains a modern build wrapper and a
  stable `k2_ebpf_equiv` command around it.
- Unsupported metadata, helpers, program types, or backend errors must return
  `UNKNOWN`, not `PASS`.
- Add CLI-visible behavior through the existing tri-state `StageResult` /
  `ValidationResult` JSON model.

## Test Expectations

Run the default gate before sending changes:

```bash
make test
```

Run the upstream Z3 release gate when touching K2, CMake, solver linkage, K2
metadata, or equivalence-wrapper behavior:

```bash
make test-k2-z3-release
```

Run the optional PREVAIL smoke when touching PREVAIL parsing, `check`
orchestration, result formatting, or the dependency scripts:

```bash
make test-prevail-smoke
```

For user-visible behavior, update the relevant docs:

- `README.md` for commands users should discover quickly.
- `docs/backend-contract.md` for backend semantics and result meanings.
- `docs/test-plan.md` for coverage claims.
- `docs/dependency-policy.md` for dependency ownership or pinning changes.

## Adding Backend Coverage

Prefer small fixtures that prove one behavior at a time:

- one supported non-identical `PASS` case for a modeled transformation;
- one supported `FAIL` case when the model can produce a counterexample;
- one conservative `UNKNOWN` case for unsupported metadata or semantics.

Keep fixtures host-stable and CI-friendly. If a test requires network access,
large upstream builds, or fragile external state, make it an opt-in gate instead
of adding it to the default `make test` path.
