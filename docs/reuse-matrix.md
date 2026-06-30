# Reuse Matrix

Last checked: 2026-06-30.

| Project | Role | Reuse value | Caveat |
| --- | --- | --- | --- |
| [`smartnic/superopt`](https://github.com/smartnic/superopt) | K2 core optimizer and equivalence checker | Best direct semantic-checking code base; MIT; has `src/isa/ebpf`, `src/verify`, `src/search` | Research artifact, older eBPF/toolchain assumptions |
| [`smartnic/sigcomm21_artifact`](https://github.com/smartnic/sigcomm21_artifact) | K2 reproduction wrapper | Useful experiments and documentation | Not the core library to fork |
| [`smartnic/bpf-elf-tools`](https://github.com/smartnic/bpf-elf-tools) | ELF extraction and patching for K2 | Useful historical object workflow | Older libbpf/object assumptions |
| [EPSO paper](https://arxiv.org/html/2511.15589v1) | Cached rewrite-rule superoptimizer | Excellent architecture for proof-carrying rule DB | No obvious public implementation found |
| [Heimdall paper](https://arxiv.org/html/2605.25411v1) | LLM migration plus Z3 equivalence | Best agent-loop blueprint | No public reusable repo found |
| [`4ar0nma0/Merlin`](https://github.com/4ar0nma0/Merlin) | Multi-tier eBPF optimizer | Optimization ideas and benchmark baseline | Not a semantic validator foundation |
| [`vbpf/prevail`](https://github.com/vbpf/prevail) | Abstract-interpretation verifier | Secondary safety check; invariant and CFG ideas | Safety, not equivalence |
| [`trailofbits/ebpf-verifier`](https://github.com/trailofbits/ebpf-verifier) | Userspace Linux verifier harness | Kernel-version verifier matrix | Older PoC; not semantic equivalence |
| [`dslab-epfl/ebpf-se`](https://github.com/dslab-epfl/ebpf-se) | KLEE-based symbolic execution | Symbolic-execution reference | Not old/new equivalence by itself |
| [`aya-rs/aya`](https://github.com/aya-rs/aya) / `aya-obj` | Rust eBPF object and loader stack | Best Rust object/parser foundation | Formal semantics still custom |
| [`cilium/ebpf`](https://github.com/cilium/ebpf) | Go eBPF object, asm, loader stack | Best Go object/loader foundation | Formal semantics still custom |
| [`libbpf/libbpf`](https://github.com/libbpf/libbpf) | Canonical C loader stack | Production compatibility and CO-RE behavior | C integration cost; not a verifier |
| [`iovisor/ubpf`](https://github.com/iovisor/ubpf) | Userspace eBPF VM | Concrete execution, replay, fuzzing | Not kernel verifier semantics |
| [`qmonnet/rbpf`](https://github.com/qmonnet/rbpf) | Rust eBPF VM/JIT | Concrete replay and differential testing | Not formal equivalence |
| [`Z3Prover/z3`](https://github.com/Z3Prover/z3) | SMT solver | Default solver for bitvectors, arrays, ITE chains | Solver results depend on sound encoding |
| [`angr/angr`](https://github.com/angr/angr) | Binary symbolic execution platform | Possible backend path, mirrors Heimdall design | Heavy dependency; eBPF support is custom |

## Best Reuse Stack

Short-term:

```text
K2/superopt checker
  + small wrapper CLI
  + Z3
  + kernel verifier load test
  + BPF_PROG_RUN concrete replay
```

Long-term:

```text
aya-obj or cilium/ebpf parser
  + custom normalized eBPF IR
  + custom symbolic executor
  + helper/map semantics registry
  + Z3 backend
  + kernel verifier matrix
  + counterexample replay
```

## Decision

Use `smartnic/superopt` as the semantic reference implementation, not as the
final architecture. Build the maintained validator around modern object tooling,
and port only the parts of K2 that remain useful:

- instruction semantics
- CFG/path summarization ideas
- equivalence-query structure
- test cases
- optimization-window concept
