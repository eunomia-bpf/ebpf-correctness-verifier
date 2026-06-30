# MVP Architecture

## Goal

Accept or reject eBPF transformations proposed by an untrusted agent, optimizer,
or migration tool.

The MVP should answer:

```text
Is the transformed eBPF program safe for the target kernel and equivalent to
the original program for the supported semantic subset?
```

## Result Model

The validator must be conservative:

```text
PASS:
  target kernel verifier accepts new program
  and old/new equivalence or refinement query is UNSAT
  and required structural checks pass

FAIL:
  target kernel verifier rejects new program
  or solver finds a concrete counterexample
  or a structural invariant is violated

UNKNOWN:
  unsupported instruction/helper/map/program type
  or timeout
  or imprecise model
  or CO-RE/relocation state cannot be pinned down
```

`UNKNOWN` is a rejection for automatic merge/deploy. It is still useful feedback
for the agent.

## Pipeline

```text
old source/object
new source/object
        |
        v
compile, relocate, and identify target programs
        |
        v
PREVAIL safety/invariant gate
        |
        v
equivalence backend
        |
        v
PASS / FAIL / UNKNOWN
```

## Analyzer-First Design

Do not start by building a new symbolic executor. Start with adapters:

- PREVAIL adapter for safety, CFG, abstract states, issue kinds, and invariants.
- K2-derived backend for existing eBPF SMT semantics and equivalence tests.
- Optional kernel adapter for target verifier logs and `BPF_PROG_RUN` replay
  after the userspace core is stable.

Only implement missing glue:

- normalized result schema
- object/program selection
- command orchestration
- counterexample/result conversion
- minimal equivalence wrappers around K2-style checks
- modern build overlay for the K2-derived code

If a custom IR becomes necessary, keep it close to eBPF and derive it from
existing analyzer outputs rather than replacing those analyzers.

## Observable Summary

For each terminating path:

```text
Summary = {
  path_condition,
  return_value,
  final_map_state,
  packet_or_context_effects,
  output_events,
  helper_trace,
  structural_facts
}
```

The core query is:

```text
exists same_input:
  feasible(old_path)
  and feasible(new_path)
  and observable_diff(old_summary, new_summary)
```

`UNSAT` means no difference was found in the modeled subset.

## Map Model

Start with symbolic maps:

```text
update(M, key, value):
  M'.present(q) = ite(q == key, true, M.present(q))
  M'.value(q)   = ite(q == key, value, M.value(q))

delete(M, key):
  M'.present(q) = ite(q == key, false, M.present(q))
  M'.value(q)   = M.value(q)

lookup(M, key):
  returns pointer(map_value, key) if M.present(key), otherwise NULL
```

This is enough to model common hash/array-map transformations before tackling
per-CPU maps, map-of-maps, LPM tries, ringbufs, and program arrays.

## Helper Model Registry

Helpers must be modeled explicitly:

```text
HelperModel = {
  helper_id,
  argument_contract,
  return_model,
  state_effects,
  observable_effects,
  unsupported_reason
}
```

Unknown helpers must return `UNKNOWN`, not "no effect."

## Initial Supported Subset

Support:

- ALU64 / ALU32 arithmetic and logic
- MOV, shifts, endian conversions
- conditional branches
- stack load/store
- packet/context read-only accesses
- `bpf_map_lookup_elem`
- `bpf_map_update_elem`
- `bpf_map_delete_elem`
- deterministic scalar helpers with symbolic returns when side-effect free

Return `UNKNOWN`:

- tail calls and program arrays
- atomics until structural checks are implemented
- packet writes
- dynptr, timers, spin locks
- ringbuf/perf-event contents unless sink tracking is enabled
- helper/kfuncs not in the registry

## Agent Integration

The agent should only see structured feedback:

```json
{
  "result": "FAIL",
  "stage": "equivalence",
  "counterexample": {
    "return_old": 2,
    "return_new": 0,
    "input_packet": "...",
    "map_state": "...",
    "divergence": "return_value"
  }
}
```

Do not let benchmark improvement override correctness.

Acceptance order:

```text
correctness first
performance second
rule learning third
```

This matches the lesson from Heimdall: compilation and kernel-verifier success
are not enough. The maintained gate must keep safety-policy failures,
equivalence counterexamples, unsupported helper models, and structural mismatches
as separate feedback classes.

## First Milestones

1. Done as an optional gate: keep a reproducible PREVAIL build and run selected
   YAML/object fixtures through `make test-prevail-smoke`.
2. Done: vendor K2/superopt and run selected eBPF tests against modern system
   Z3.
3. Done: add a local CLI that emits JSON for `PASS`, `FAIL`, and `UNKNOWN`.
4. Done for the first supported slice: extract a K2-derived old/new equivalence
   command and wire it into `ebpf-tv check --equiv-backend k2`.
5. Done: run Python, K2, and ELF-section integration tests in GitHub Actions
   through the same `make test` entrypoint used locally.
6. In progress: add real object fixtures and mutation tests. CI now covers a
   clang-produced object, ALU and stack-memory equivalent section rewrites, and
   a return-value counterexample; broader helper/map/packet fixtures remain.
   Track coverage in `docs/test-plan.md`.
7. In progress: add K2 environment handling. A no-map constant-input default is
   generated automatically; map/desc/BTF/CO-RE extraction remains.
8. Add Heimdall-derived fixtures for maps, globals, output sinks, atomics, and
   entry-point type checks as backend coverage becomes available.
9. Add optional kernel verifier load gate and `BPF_PROG_RUN` replay.
10. Add agent-facing JSON feedback.
