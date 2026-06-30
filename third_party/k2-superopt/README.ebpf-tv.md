# K2 / superopt Vendor Notes

This directory vendors the public K2 core implementation from:

```text
https://github.com/smartnic/superopt
vendored commit: f50ee1f
license: MIT
```

The original project is a research artifact for K2, the BPF superoptimizer. It
contains the closest available open eBPF equivalence-checking implementation and
many useful tests for instruction semantics, maps, packets, and program
equivalence.

`ebpf-tv` does not use K2's original top-level Makefile as the maintained entry
point because that Makefile expects an old sibling Z3 checkout at
`../z3/build/config.mk`. Instead, the repository root contains a CMake smoke
target that compiles K2's eBPF instruction/codegen test against the system Z3
headers and library.

The next modernization step is to extract a small old/new equivalence CLI from
`src/verify` and `src/isa/ebpf` while preserving K2's original MIT license and
provenance.
