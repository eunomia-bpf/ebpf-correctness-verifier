# Reproduction Notes

Last run: 2026-06-30.

Host:

- Ubuntu 24.04
- CMake 3.28.3
- GCC 13.3.0
- Clang 18.1.3
- no system `z3` command at start

Scratch directory:

```bash
/tmp/ebpf-correctness-repro
```

## PREVAIL

Repository:

```text
https://github.com/vbpf/prevail
commit 865b701
```

Build:

```bash
git clone --depth 1 --recurse-submodules --shallow-submodules \
  https://github.com/vbpf/prevail.git /tmp/ebpf-correctness-repro/prevail
cd /tmp/ebpf-correctness-repro/prevail
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Result:

- `libprevail.a`, `bin/tests`, and `bin/run_yaml` built successfully.
- `prevail-cli` needed a local compatibility patch for
  `PREVAIL_VERSION_STRING` expansion on current CMake/compiler combinations.

Compatibility patch used by `make test-prevail-smoke`:

```diff
-    app.set_version_flag("--version", PREVAIL_VERSION_STRING);
+    app.set_version_flag("--version", "prevail-smoke");
```

This only affects the smoke-built CLI's `--version` output; it does not change
the verifier library or analysis behavior.

Representative runs:

```bash
./bin/run_yaml test-data/add.yaml -q
./bin/run_yaml test-data/map.yaml -q
./bin/run_yaml test-data/packet.yaml -q
./bin/run_yaml test-data/loop.yaml -q
```

Observed result:

- add/range examples passed
- map address/fd/value examples passed
- packet read/write/bounds examples passed
- loop and termination examples passed

Object tests:

```bash
./bin/tests "libbpf-bootstrap/minimal.bpf.o*"
./bin/tests "*invalid*"
./bin/tests "linux-selftests/map_ptr_kern.o check_array_of_maps"
```

Observed result:

- `libbpf-bootstrap/minimal.bpf.o*`: all tests passed, 4 assertions in 1 test.
- `*invalid*`: 55 passed, 3 failed as expected; failures were classified as
  bounds, map typing, and type-tracking issues.
- `check_array_of_maps`: failed as expected with `VerifierTypeTracking`.

CLI smoke tests after the local quoting patch:

```bash
./bin/prevail -l ebpf-samples/libbpf-bootstrap/minimal.bpf.o
./bin/prevail ebpf-samples/libbpf-bootstrap/minimal.bpf.o tp/syscalls/sys_enter_write
./bin/prevail ebpf-samples/invalid/invalid-lddw.o .text func
```

Observed result:

- listed `section=tp/syscalls/sys_enter_write function=handle_tp`
- returned `PASS: tp/syscalls/sys_enter_write/handle_tp`
- rejected invalid lddw with `unmarshaling error at 1: incomplete lddw`

Automated smoke entrypoint:

```bash
make test-prevail-smoke
```

This clones the pinned PREVAIL commit into `.cache/prevail` by default, applies
the compatibility patch above, builds `prevail` and `run_yaml`, and runs
`add.yaml`, `map.yaml`, and the minimal object smoke.

Conclusion:

PREVAIL is the right first substrate for safety, CFG, abstract interpretation,
fixtures, and issue classification. It should be integrated before writing any
new symbolic-execution code.

## K2 / superopt

Repository:

```text
https://github.com/smartnic/superopt
commit f50ee1f
```

K2 expects an old Z3 checkout as a sibling directory:

```text
https://github.com/Z3Prover/z3
commit 1c7d27b
```

Setup:

```bash
git clone --depth 1 https://github.com/smartnic/superopt.git \
  /tmp/ebpf-correctness-repro/superopt
git clone --depth 1 https://github.com/Z3Prover/z3.git \
  /tmp/ebpf-correctness-repro/z3
cd /tmp/ebpf-correctness-repro/z3
git fetch --depth 1 origin 1c7d27bdf31ca038f7beee28c41aa7dbba1407dd
git checkout 1c7d27bdf31ca038f7beee28c41aa7dbba1407dd
python3 scripts/mk_make.py
cd build
make -j$(nproc)
```

Then:

```bash
cd /tmp/ebpf-correctness-repro/superopt
make run_ebpf_tests
```

Observed result:

- old Z3 built successfully
- K2/superopt built its eBPF test binaries
- `main_ebpf.out` ran the hello-world optimization harness
- instruction SMT tests passed for many ALU, endian, shift, branch, memory, and
  atomic cases
- map helper tests passed for lookup/update/delete, map equivalence, multiple
  maps, and map helper return values
- packet equivalence tests mostly passed
- full `run_ebpf_tests` aborted in `validator_test_ebpf`:

```text
validator_test_ebpf.out: src/isa/ebpf/inst_codegen.cc:1536:
uint64_t get_uint64_from_bv64(z3::expr&, bool): Assertion `false' failed.
make: *** [Makefile:192: run_ebpf_tests] Aborted (core dumped)
```

Conclusion:

K2 is valuable as an equivalence-semantics reference and test corpus, especially
for map/helper and packet cases. It is not stable enough to be the only harness
without triage and selective test curation.

## eBPF-SE

Repository:

```text
https://github.com/dslab-epfl/ebpf-se
commit 47a0518
```

Attempted command:

```bash
cd /tmp/ebpf-correctness-repro/ebpf-se/examples/fw
make symbex
```

Observed result:

```text
/usr/bin/time: cannot run klee: No such file or directory
make: *** [../Makefile:81: symbex] Error 127
```

The setup script installs LLVM 12, KLEE, KLEE-uClibc, and Z3. It uses
`sudo apt-get` by default for system packages, so it should be containerized
before becoming part of the standard reproduction flow.

Conclusion:

eBPF-SE should be kept as a symbolic-execution baseline, but not as the default
host-level dependency. The next step is a Dockerfile or devcontainer that pins
LLVM 12/KLEE/Z3 and runs one small XDP example plus Katran.
