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
K2/equivalence gate for supported slices or whole programs
        |
        v
kernel verifier gate
        |
        v
counterexample replay, BPF_PROG_RUN, and benchmark gate
```

## Analyzer-First Design

Do not start by building a new symbolic executor. Start with adapters:

- PREVAIL adapter for safety, CFG, abstract states, issue kinds, and invariants.
- K2 adapter for existing eBPF SMT semantics and equivalence tests.
- eBPF-SE adapter for KLEE path exploration on examples where setup cost is
  acceptable.
- Kernel adapter for target verifier logs and `BPF_PROG_RUN` replay.

Only implement missing glue:

- normalized result schema
- object/program selection
- command orchestration
- counterexample/result conversion
- minimal equivalence wrappers around K2-style checks

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

## First Milestones

1. Keep a reproducible PREVAIL build and run selected YAML/object fixtures.
2. Keep a reproducible K2/superopt build and run selected eBPF tests, including
   map helper and packet-equivalence tests.
3. Containerize eBPF-SE so KLEE/LLVM 12 setup does not mutate the host.
4. Add a local `repro` script that runs the stable subset and emits JSON.
5. Define adapter result schemas for `PASS`, `FAIL`, `UNKNOWN`, and
   `UNSUPPORTED`.
6. Add kernel verifier load gate and `BPF_PROG_RUN` replay for accepted objects.
7. Add agent-facing JSON feedback.
