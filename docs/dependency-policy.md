# Dependency Policy

Last checked: 2026-07-01.

This project should stay a thin translation-validation frontend over reused
analysis and equivalence engines. Dependency ownership follows that rule: vendor
only the code this repository must patch or wrap tightly, and keep external
tools external when a stable binary interface is enough.

## Current Policy

| Dependency | Policy | Default path | Reason |
| --- | --- | --- | --- |
| K2 / `smartnic/superopt` | Vendored source | `third_party/k2-superopt` | This project modernizes and wraps K2 directly: root CMake, system-Z3 linkage, curated eBPF smoke tests, and `k2_ebpf_equiv`. |
| Z3 | System package | `libz3-dev`, found by CMake | The project uses Z3 as a solver library, not as code to modify. System packages keep checkout and CI small while still testing modern Z3 integration. |
| PREVAIL | External binary plus optional pinned smoke | `--prevail-bin`, `make test-prevail-smoke` | `ebpf-tv` consumes PREVAIL through its CLI contract. The default build should not require Boost/PREVAIL sources or PREVAIL's own submodules. |

## Submodule Rules

Do not add Z3 as a submodule in the default repository. If exact solver
reproducibility is needed, prefer a container, Nix/devcontainer file, or CI
image pin over vendoring the solver source.

Do not add PREVAIL as a default submodule. The maintained interface is:

```bash
ebpf-tv check OLD.o NEW.o --section xdp --prevail-bin /path/to/prevail
```

The optional PREVAIL gate is intentionally separate:

```bash
make test-prevail-smoke
```

That target clones a pinned PREVAIL commit into `.cache/prevail` by default,
applies the compatibility patch documented in `docs/reproduction-notes.md`,
builds `prevail` and `run_yaml`, and runs a small smoke suite. This keeps the
normal checkout, `make test`, and CI path lightweight.

## When A New Vendored Dependency Is Acceptable

Vendoring or adding a submodule is acceptable only when all of these are true:

- this repository needs to patch, modernize, or compile against source-level
  internals;
- there is no stable CLI, library, or package interface that covers the need;
- the default `make test` path remains reproducible on fresh CI;
- provenance, license, pinned commit, and local changes are documented;
- unsupported or missing optional dependencies produce `UNKNOWN`, not `PASS`.

K2 satisfies these conditions today. Z3 and PREVAIL do not for the default
development path.

## Artifact Reproduction

A future artifact profile may add optional scripts, containers, or a separate
checkout helper that pins PREVAIL and Z3 more tightly. That profile should be
opt-in and should not change the default dependency policy above.
