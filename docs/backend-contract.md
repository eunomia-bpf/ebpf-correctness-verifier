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

Production equivalence must use either `--equiv-backend k2` or
`--equiv-backend external`. The external command contract is:

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

The project exposes K2 through `ebpf-tv check --equiv-backend k2`:

```bash
ebpf-tv check OLD.o NEW.o \
  --section xdp \
  --prevail-bin /path/to/prevail \
  --equiv-backend k2 \
  --k2-equiv build/k2_ebpf_equiv \
  --k2-root third_party/k2-superopt
```

The first extracted internal backend is `k2_ebpf_equiv`:

```bash
build/k2_ebpf_equiv \
  --old OLD.ins \
  --new NEW.ins \
  --map PROGRAM.maps \
  --desc PROGRAM.desc \
  --k2-root third_party/k2-superopt
```

It uses K2's raw eBPF instruction reader, benchmark metadata reader, and
`validator::is_equal_to` implementation. The project-owned wrapper only handles
argument validation, K2 working-directory setup, noisy stdout isolation, JSON
result formatting, and exit-code normalization:

```text
exit 0 -> PASS,    K2 proved equivalence
exit 1 -> FAIL,    K2 produced a semantic counterexample
exit 2 -> UNKNOWN, unsupported instruction/model path, malformed input, or K2 error
```

Current scope:

- `ebpf-tv` dumps one ELF section from each object using `llvm-objcopy` or
  `objcopy`
- `k2_ebpf_equiv` checks raw K2 `.ins` bytecode inputs
- one shared K2 environment for old/new
- automatic K2 `.maps` generation from matching legacy ELF `maps` sections
  containing `struct bpf_map_def` records when `--k2-map` is omitted
- generated empty-map constant-input environment when no legacy `maps` section
  exists and `--k2-map`/`--k2-desc` are omitted
- `FAIL` when old/new legacy map metadata differs before equivalence checking
- explicit `.maps` and `.desc` overrides for programs that need packet, context,
  or map modeling
- in-process system Z3, not K2's old z3server path
- smoke-tested on generated raw eBPF programs and clang-produced ELF objects
  for byte-identical PASS, ALU and stack-memory equivalent rewrites, and
  semantic FAIL
- raw-backend smoke coverage for explicit map metadata and packet-input
  metadata, including supported PASS and FAIL cases
- ELF-section frontend coverage for explicit map metadata, automatic legacy map
  extraction, and packet-input metadata through `ebpf-tv check --equiv-backend
  k2`

Known gaps:

- no automatic program description extraction yet; generated `.desc` metadata is
  intentionally only a simple default unless overridden
- no modern BTF `.maps` extraction or CO-RE relocation modeling yet
- complex K2 fixtures can still hit old unsupported pointer-model paths and must
  return `UNKNOWN`
