# Heimdall Notes

Last checked: 2026-06-30.

Paper: [Heimdall: Formally Verified Automated Migration of Legacy eBPF Programs to Rust](https://arxiv.org/html/2605.25411v1).

## Classification

Heimdall is the strongest recent blueprint for an agent-facing eBPF
translation-validation loop, but I did not find a public implementation that can
be reused as this project's first backend.

Use it as:

- an architecture reference for compile, kernel verifier, safety-policy, and
  equivalence feedback loops
- an evaluation reference for showing that kernel-verifier success is not enough
- a source of target fixtures for maps, globals, output sinks, atomics, and
  helper modeling

Do not treat it as:

- a drop-in equivalence backend today
- evidence that this project should implement a new symbolic executor first
- a replacement for PREVAIL as the safety/invariant backend or K2 as the first
  reusable bytecode-equivalence backend

## Pipeline

Heimdall validates C-to-Rust/Aya migrations with five stages:

1. Translate legacy libbpf C to Rust/Aya.
2. Compile the Rust candidate and load it through the kernel verifier.
3. Run source-level safety-policy checks over the generated Rust.
4. Symbolically execute the old and new eBPF bytecode with an angr extension.
5. Check Z3 equivalence and feed counterexamples back to the translator.

For this project, the important transferable shape is not the C-to-Rust
migration front end. It is the result discipline:

```text
compile/load pass
AND safety policy pass
AND bytecode-level equivalence pass
```

That maps directly onto this project's gate:

```text
PREVAIL(old) PASS
AND PREVAIL(new) PASS
AND equivalence(old, new) PASS
```

## Equivalence Model

Heimdall's backend is bytecode-level, not source-level. It extends angr with:

- an eBPF ELF loader
- an eBPF architecture definition
- a VEX lifter for eBPF instructions
- helper models exposed through angr SimProcedures
- a formula generator that emits path summaries

Each symbolic path summary contains:

- path predicate
- return value in `r0`
- final map state
- mutable global state
- output-sink effects when the stricter mode is enabled

The map model is especially relevant. Heimdall does not rely directly on Z3
arrays through Claripy. Instead, it post-processes map writes into bitvector ITE
chains, preserving last-write-wins behavior for symbolic keys and supporting
both helper-mediated updates and pointer writes into map values.

The paper also adds structural checks around the SMT result:

- entry-point/program-type compatibility before symbolic execution
- mutable-global pairing across binaries
- atomic-opcode count checks, because single-path symbolic execution can miss
  dropped atomicity

These should become target requirements for future backends, including any K2
extension or future Heimdall adapter.

## Evaluation Lessons

The main evaluation lesson is that compilation and kernel-verifier acceptance
are weak correctness signals.

The paper reports that baseline agents can produce compiled Rust artifacts for
all evaluated programs, yet only a small fraction pass the full downstream
triple gate. It also reports that many kernel-verifier-passing translations
still fail either the safety policy or bytecode equivalence check.

The failure distribution is useful for this project's tests:

- map-value mismatches are a dominant equivalence-failure class
- state-representation mismatches between globals and maps are also common
- helper-call and pointer-tracking failures still appear at the kernel verifier
  stage
- full-program symbolic execution can time out on larger programs

This supports a conservative result model: unsupported helpers, path explosion,
unmodeled sinks, or imprecise map/global modeling must return `UNKNOWN`, not
`PASS`.

## Reuse Decision

The best current implementation decision remains:

1. Keep PREVAIL as the userspace safety, CFG, invariant, and issue-classification
   backend.
2. Keep the vendored K2-derived checker as the first small bytecode-equivalence
   backend.
3. Add Heimdall-shaped tests and result fields as the supported slice expands.
4. If Heimdall's angr backend is released, evaluate it as an optional
   `--equiv-backend heimdall` adapter instead of reimplementing it here.

This project should not manually implement an angr eBPF loader, VEX lifter,
helper-stub library, and ITE formula generator unless no reusable release exists
and the paper artifact explicitly needs that component.

## Candidate Fixtures

Good future fixtures derived from Heimdall's examples:

- hash-map counter: lookup hit mutates a map value, lookup miss inserts a value
- map update/delete ordering with symbolic keys
- global-versus-map state representation mismatch
- output-sink equivalence in default sink mode and strict byte-comparison mode
- entry-point section mismatch, for example XDP versus TC context
- dropped atomic operation must fail even when return/map formulas match
- helper failure mode where source and target differ on typed error handling

These should be added only when the selected backend can model the feature
conservatively.
