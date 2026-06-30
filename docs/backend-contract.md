# Backend Contract

`ebpf-tv` is intentionally thin. It owns command orchestration, a conservative
tri-state result model, and test fixtures. It does not reimplement PREVAIL or
K2-style equivalence algorithms.

## Result Model

Every backend returns one of:

- `PASS`: the backend proved or accepted the requested property in its supported
  model.
- `FAIL`: the backend found a verifier rejection, semantic counterexample, or
  malformed program.
- `UNKNOWN`: the backend cannot decide because the tool is missing, unsupported,
  timed out, or returned unrecognized output.

The top-level result is:

```text
FAIL    if any stage is FAIL
UNKNOWN if no stage is FAIL and at least one stage is UNKNOWN
PASS    only if every stage is PASS
```

## PREVAIL Backend

Purpose:

- safety analysis
- CFG and abstract-interpretation baseline
- issue classification for invalid objects

Invocation:

```bash
prevail OLD_OR_NEW.o SECTION [FUNCTION]
```

The backend is considered:

- `PASS` when output contains `PASS:`
- `FAIL` when output contains a verifier or unmarshalling rejection
- `UNKNOWN` when the requested section/function cannot be found or the tool is
  unavailable

## Equivalence Backend

The default `identity` backend is only a smoke backend:

- byte-identical objects are `PASS`
- non-identical objects are `UNKNOWN`

Production equivalence must use `--equiv-backend external`. The external command
contract is:

```text
exit 0 -> PASS
exit 1 -> FAIL
exit 2 -> UNKNOWN
other  -> UNKNOWN
```

Arguments can use these placeholders:

- `{old}`
- `{new}`
- `{section}`
- `{function}`

## K2-Derived Backend

K2 source is vendored under `third_party/k2-superopt` with its original MIT
license. The repository also provides a modern CMake smoke target,
`k2_ebpf_inst_codegen_test`, that builds K2's eBPF instruction and map-helper
semantics test against the system Z3 library.

This is not yet a complete old/new object equivalence backend. It is the first
maintainable step toward extracting K2's useful equivalence core without keeping
its old build system as the project entrypoint.
