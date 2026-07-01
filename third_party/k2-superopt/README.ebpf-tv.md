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
`../z3/build/config.mk`. Instead, the repository root contains CMake targets
that compile K2's eBPF instruction/codegen smoke test and the
`k2_ebpf_equiv` old/new equivalence wrapper against the system Z3 headers and
library. The repository also provides `make test-k2-z3-release`, which rebuilds
the same targets against the pinned official upstream Z3 release used by CI.

The wrapper preserves K2's original MIT license and provenance. It only adds
argument validation, JSON result formatting, normalized exit codes, and
`--version` output reporting the vendored K2 commit and linked system Z3
version.
