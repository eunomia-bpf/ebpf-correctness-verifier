# Research Survey: eBPF Transformation Correctness

Last checked: 2026-06-30.

## Summary

There is prior work for almost every piece of the system, but no maintained,
general-purpose "Alive2 for eBPF" that can be reused as a complete correctness
validator today.

The strongest finding is:

- K2 is the closest reusable implementation for bytecode optimization plus
  semantic equivalence checking.
- Heimdall is the closest architecture for an LLM/agent loop with formal
  counterexample feedback, but it is currently best treated as a paper blueprint.
- EPSO is the most relevant design for caching proven rewrite rules, but there
  is no obvious public implementation to reuse.
- PREVAIL, Trail of Bits' verifier harness, VEP, Agni, and kernel verifier work
  are about safety, verifier compatibility, or verifier soundness. They are
  useful gates and references, but they do not replace semantic equivalence.

## What Must Be Proven

The Linux verifier proves safety properties such as initialized stack reads,
bounded memory access, helper argument constraints, pointer type discipline, and
termination-related constraints. It does not prove that two programs have the
same behavior.

For transformation correctness we need a relation such as:

```text
for all allowed inputs, contexts, helper outcomes, and initial map states:
observable_behavior(old_program) == observable_behavior(new_program)
```

Observable behavior can include:

- return value, for example `XDP_PASS`, `XDP_DROP`, or `TC_ACT_*`
- map lookup/update/delete effects
- packet or context memory effects
- ringbuf/perf-event output
- helper/kfunc side effects
- tail-call behavior
- atomicity-sensitive behavior

For optimization and migration, exact equivalence is often the right target.
For policy changes, a refinement property is usually better, for example "a
packet dropped by the old program must not be passed by the new program."

## Prior Work

### K2 / smartnic/superopt

K2 is the most direct predecessor. The paper and artifact describe a
program-synthesis-based compiler that optimizes BPF bytecode with formal
correctness and safety guarantees. The public implementation is split across the
SIGCOMM artifact and the core [`smartnic/superopt`](https://github.com/smartnic/superopt)
repository.

Useful implementation pieces in `smartnic/superopt`:

- `src/isa/ebpf`: eBPF instruction representation and canonicalization.
- `src/verify`: CFG, SMT program construction, validator, and Z3 client.
- `src/search`: stochastic search machinery.
- `bpf-elf-tools`: ELF extraction and patching support used by the older K2
  flow.

Why it matters:

- It already lowers eBPF instructions into first-order/bit-vector constraints.
- It was designed around equivalence checking inside an optimizer loop.
- It has an MIT license.

Caveats:

- It is research-artifact quality and last materially active around the K2 era.
- It predates several modern eBPF features and modern libbpf/CO-RE workflows.
- It should be mined and wrapped before it is trusted as infrastructure.

### Heimdall

Heimdall is the closest match for an agent-driven eBPF correctness loop. It uses
LLMs to migrate legacy libbpf C programs to Aya Rust, then checks the generated
bytecode against the original with symbolic execution and Z3. Its design also
feeds structured counterexamples back to the LLM, which is exactly the loop an
agent optimizer should use.

Most relevant ideas:

- bytecode-level validation rather than source-level validation
- symbolic execution summaries per path
- shared symbolic variables for old/new program inputs
- map modeling with write chains / ITE-style lookup semantics
- explicit output sink modeling for ringbuf/perf output
- `UNKNOWN` behavior when helper or model coverage is insufficient

Caveat: I did not find a public repository that can be used directly. Treat the
paper as a design reference, not as reusable code.

### EPSO

EPSO proposes a caching-based BPF superoptimizer. The key idea is to discover
rewrite rules offline using superoptimization and equivalence checking, then
reuse those rules online with low overhead.

This is a strong fit for an agent optimizer:

```text
offline:
  agent / synthesizer proposes rewrite rule
  validator proves equivalence under preconditions
  rule database stores proven rule

online:
  match rule against bytecode slice
  instantiate rule
  re-check safety and equivalence
```

Caveat: I found the paper, but not a public implementation that looks ready to
reuse.

### Merlin

Merlin is a multi-tier optimizer for eBPF with public MIT-licensed code. It is
useful as an optimizer baseline and source of eBPF-specific optimization ideas.
It is not the best correctness-validator foundation because its core goal is
compiler optimization passes, not a reusable semantic equivalence checker.

### PREVAIL

PREVAIL is an actively maintained abstract-interpretation-based eBPF verifier.
It is valuable for:

- a second safety gate
- invariant extraction
- verifier research comparison
- faster local analysis than target-kernel loading in some workflows

It should not be presented as transformation correctness by itself. It checks
safety, not old/new semantic equivalence.

### Trail of Bits eBPF verifier harness

The Trail of Bits verifier harness isolates the Linux kernel verifier so a
program can be checked against multiple kernel versions/configurations without
manually booting each kernel. It is useful for compatibility CI and target
kernel matrix checks.

Caveat: the public repository appears older and narrower than a maintained
production service.

### eBPF-SE

eBPF-SE is a KLEE-based symbolic execution tool for eBPF programs. It is useful
as a symbolic-execution reference and for path exploration experiments. It is
not a complete old/new equivalence checker.

### VEP and Proof-Carrying eBPF Work

VEP is a two-stage verification toolchain for annotated eBPF-C and annotated
bytecode with a lightweight proof checker. This is adjacent but different:
it proves user-specified correctness properties for annotated programs, not
equivalence of arbitrary old/new transformations.

This line is important if the project later evolves from equivalence checking
to proof-carrying rewrite rules or policy/invariant proofs.

### Agni and Verifier-Soundness Work

Agni and related work validate parts of the Linux verifier itself, especially
range-analysis soundness. This matters because the kernel verifier is part of
the trusted base, but it is not a transformation validator.

## Technical Options

### Option A: Fork K2/superopt

Best for the fastest semantic-checking prototype.

Pros:

- closest existing code to the target
- already has Z3-backed eBPF equivalence machinery
- MIT licensed
- maps directly to the agent optimizer architecture

Cons:

- research code shape
- older object-tooling assumptions
- likely weak coverage for modern helpers, kfuncs, CO-RE, BTF, atomics, dynptr,
  and newer verifier behavior

Use this to reproduce, understand, and bootstrap. Do not stop here.

### Option B: Clean Rust Validator on aya-obj

Best long-term infrastructure path for eunomia-bpf.

Pros:

- modern eBPF object parsing with BTF and relocations
- clean library boundary for a validator
- good fit with existing Rust-based BPFix/verifier-analysis work
- easier to expose as CLI, library, and agent gate

Cons:

- more implementation work
- symbolic execution and helper models must be built
- Z3 bindings and SMT expression management need careful design

This is my recommended main implementation path.

### Option C: Go Validator on cilium/ebpf

Best for fast integration with mature loader/object tooling.

Pros:

- very mature eBPF library
- strong object, BTF, asm, loading, and debugging support
- easy to integrate `BPF_PROG_RUN` and verifier log workflows

Cons:

- less natural if the formal core wants Rust-style type boundaries
- SMT expression layer must still be custom

This is a good alternative if the team wants Go ecosystem integration.

### Option D: angr or KLEE-Based Symbolic Execution

Best if the goal is rapid symbolic-execution research rather than a compact
validator library.

Pros:

- existing symbolic execution infrastructure
- Heimdall demonstrates that angr can be extended for eBPF
- eBPF-SE demonstrates a KLEE-based route

Cons:

- heavier dependencies
- harder to make a small, auditable checker
- equivalence-specific modeling still needs custom work

### Option E: LLVM IR / Alive2 First

Useful as a supplementary pass, but insufficient as the final gate.

Pros:

- Alive2 is mature for LLVM IR translation validation
- catches many source/IR optimization mistakes before BPF lowering

Cons:

- eBPF behavior depends on LLVM BPF lowering, BTF/CO-RE relocation, loader
  behavior, target kernel verifier behavior, helper ABI, and JIT/runtime details
- final acceptance still needs bytecode-level checking

## Recommended Direction

Build the project as an "eBPF Alive2" with an agent-facing API:

```text
old.o, new.o, target kernel/BTF, equivalence mode
        |
        v
normalize bytecode
        |
        v
kernel verifier compatibility gate
        |
        v
symbolic executor with helper/map models
        |
        v
Z3 old/new observable-difference query
        |
        v
PASS / FAIL(counterexample) / UNKNOWN
```

The novelty is not that equivalence checking exists. The novelty opportunity is
to make it usable and reusable for modern eBPF:

- maintained object/CO-RE/BTF integration
- explicit helper and map semantics library
- target-kernel verifier matrix
- counterexample feedback for agents
- proof-carrying rewrite-rule database
- conservative `UNKNOWN` handling for unsupported features

## Initial Scope

Support first:

- ALU64 / ALU32
- MOV, shifts, endian conversions
- conditional branches
- stack loads/stores
- packet/context read-only access
- simple map helpers: lookup, update, delete
- deterministic helpers with symbolic outputs where appropriate

Return `UNKNOWN` first:

- tail calls
- unbounded or hard-to-summarize loops
- atomics without structural checks
- ringbuf/perf output unless sink tracking is enabled
- dynptr, timers, spin locks
- unsupported kfuncs/helpers
- packet mutation without an explicit memory model

## Sources

- K2 paper: <https://arxiv.org/abs/2103.00022>
- K2 artifact: <https://github.com/smartnic/sigcomm21_artifact>
- K2 core implementation: <https://github.com/smartnic/superopt>
- EPSO paper: <https://arxiv.org/html/2511.15589v1>
- Heimdall paper: <https://arxiv.org/html/2605.25411v1>
- Merlin implementation: <https://github.com/4ar0nma0/Merlin>
- PREVAIL: <https://github.com/vbpf/prevail>
- Trail of Bits eBPF verifier harness: <https://github.com/trailofbits/ebpf-verifier>
- eBPF-SE: <https://github.com/dslab-epfl/ebpf-se>
- VEP paper: <https://www.usenix.org/conference/nsdi25/presentation/wu-xiwei>
- Linux verifier docs: <https://docs.kernel.org/bpf/verifier.html>
- Linux `BPF_PROG_RUN` docs: <https://docs.kernel.org/bpf/bpf_prog_run.html>
- libbpf overview: <https://docs.kernel.org/bpf/libbpf/libbpf_overview.html>
