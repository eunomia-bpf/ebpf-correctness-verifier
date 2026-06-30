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
compile and normalize
        |
        v
apply or record target BTF/CO-RE relocation
        |
        v
extract entry program bytecode
        |
        v
kernel verifier gate
        |
        v
build CFG and symbolic summaries
        |
        v
compare observable behavior with Z3
        |
        v
counterexample replay and benchmark gate
```

## Internal IR

The first validator IR should be intentionally close to eBPF:

- fixed register file `r0` through `r10`
- 64-bit and 32-bit ALU semantics
- explicit stack object
- explicit packet/context object
- map values as separate symbolic objects
- helper calls as model-table entries
- path condition per exit path

Avoid inventing a high-level IR until there is duplicated complexity to remove.

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

1. Reproduce one K2/superopt equivalence-checking example.
2. Extract a minimal eBPF instruction normalizer from object files.
3. Implement helper-free symbolic execution for straight-line ALU programs.
4. Add branch/path support.
5. Add stack load/store support.
6. Add map lookup/update/delete model.
7. Add kernel verifier load gate and `BPF_PROG_RUN` replay.
8. Add agent-facing JSON feedback.
