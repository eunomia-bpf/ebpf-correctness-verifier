# K2 XDP Equivalence Example

This example runs the public `ebpf-tv check` CLI over two clang-produced XDP
objects. The objects are patched to contain different eBPF bytecode:

- old: `r0 = 1; exit`
- new: `r0 = 0; r0 += 1; exit`

The bytecode is not identical, so the default identity backend would return
`UNKNOWN`. With the K2 backend, `ebpf-tv` extracts the XDP section, generates the
K2 packet input description from the section name, and proves the programs
equivalent.

Build the K2 backend and run the example:

```bash
make test-example-k2-xdp
```

The script uses a fake PREVAIL command that returns `PASS`, because the purpose
of this example is to demonstrate the K2 equivalence path. The real PREVAIL
build is covered separately by `make test-prevail-smoke`.

By default the script runs `python3 -m ebpf_tv` from the current checkout. Set
`EBPF_TV=/path/to/ebpf-tv` to exercise an installed CLI instead.
