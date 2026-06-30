# Reuse Matrix

Last checked: 2026-06-30.

| Project | Role | Reuse value | Caveat |
| --- | --- | --- | --- |
| [`vbpf/prevail`](https://github.com/vbpf/prevail) | Abstract-interpretation verifier | Best first substrate for safety, CFG, invariants, object fixtures, and issue classification | Safety, not old/new semantic equivalence |
| [`smartnic/superopt`](https://github.com/smartnic/superopt) | K2 core optimizer and equivalence checker | Best direct semantic-checking reference; MIT; has `src/isa/ebpf`, `src/verify`, `src/search` | Research artifact; full eBPF test run currently aborts in one validator path on this host |
| [`smartnic/sigcomm21_artifact`](https://github.com/smartnic/sigcomm21_artifact) | K2 reproduction wrapper | Useful experiments and documentation | Not the core library to fork |
| [`smartnic/bpf-elf-tools`](https://github.com/smartnic/bpf-elf-tools) | ELF extraction and patching for K2 | Useful historical object workflow | Older libbpf/object assumptions |
| [EPSO paper](https://arxiv.org/html/2511.15589v1) | Cached rewrite-rule superoptimizer | Excellent architecture for proof-carrying rule DB | No obvious public implementation found |
| [Heimdall paper](https://arxiv.org/html/2605.25411v1) | LLM migration plus symbolic-execution/Z3 equivalence | Best newer agent-loop blueprint; reports 96/102 proven-equivalent migrations | No public reusable backend found; angr/eBPF lifting would still be substantial custom code |
| [`4ar0nma0/Merlin`](https://github.com/4ar0nma0/Merlin) | Multi-tier eBPF optimizer | Optimization ideas and benchmark baseline | Not a semantic validator foundation |
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

Implemented v0:

```text
PREVAIL safety/invariant gate
  + vendored K2/superopt source
  + modern-Z3 K2 raw-instruction equivalence backend
  + ebpf-tv JSON frontend
  + conservative equivalence backend contract
```

Long-term:

```text
adapter harness over PREVAIL, K2, eBPF-SE, kernel verifier, BPF_PROG_RUN
  + normalized result schema
  + proof/refinement rule database
  + selective custom semantics only where no analyzer covers the feature
```

## Decision

Use PREVAIL as the first runnable analysis base. Use `smartnic/superopt` as the
semantic reference implementation and test source, with a maintained wrapper
around the useful K2 equivalence path. Heimdall is newer than K2 as a system
design, but without a reusable release it should influence the agent feedback
loop and evaluation, not replace K2/PREVAIL as the first implementation base.
Build the maintained project around adapters and reproducible experiments before
writing new verifier or symbolic-execution code.

Port or wrap only the parts that remain useful:

- PREVAIL CFG, abstract states, safety result, and issue-kind output
- K2 instruction semantics, map model tests, equivalence-query structure, and
  optimization-window concept
- eBPF-SE example setup and KLEE path-count outputs
