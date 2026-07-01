#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K2_EQUIV="${K2_EQUIV:-$ROOT/build/k2_ebpf_equiv}"
K2_ROOT="${K2_ROOT:-$ROOT/third_party/k2-superopt}"
CLANG="${CLANG:-clang}"
OBJCOPY="${OBJCOPY:-llvm-objcopy}"

if [ ! -x "$K2_EQUIV" ]; then
  echo "missing $K2_EQUIV; run make test-k2-smoke first" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/base.c" <<'EOF'
#define SEC(NAME) __attribute__((section(NAME), used))
SEC("xdp") int prog(void *ctx) { return 1; }
char _license[] SEC("license") = "GPL";
EOF

"$CLANG" -target bpf -O2 -g0 -c "$tmp/base.c" -o "$tmp/base.o"

python3 - "$tmp/old.ins" "$tmp/new.ins" <<'PY'
from pathlib import Path
import struct
import sys

BPF_ALU64_ADD_K = 0x07
BPF_ALU64_MOV_K = 0xB7
BPF_EXIT = 0x95


def insn(opcode, dst=0, src=0, off=0, imm=0):
    regs = (dst & 0x0F) | ((src & 0x0F) << 4)
    return struct.pack("<BBhi", opcode, regs, off, imm)


old = insn(BPF_ALU64_MOV_K, dst=0, imm=1) + insn(BPF_EXIT)
new = (
    insn(BPF_ALU64_MOV_K, dst=0, imm=0)
    + insn(BPF_ALU64_ADD_K, dst=0, imm=1)
    + insn(BPF_EXIT)
)

Path(sys.argv[1]).write_bytes(old)
Path(sys.argv[2]).write_bytes(new)
PY

"$OBJCOPY" --update-section=xdp="$tmp/old.ins" "$tmp/base.o" "$tmp/old.o"
"$OBJCOPY" --update-section=xdp="$tmp/new.ins" "$tmp/base.o" "$tmp/new.o"

cat >"$tmp/prevail" <<'EOF'
#!/usr/bin/env sh
echo "PASS: $2/prog"
EOF
chmod +x "$tmp/prevail"

if [ -n "${EBPF_TV:-}" ]; then
  cli=("$EBPF_TV")
else
  export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
  cli=(python3 -m ebpf_tv)
fi

"${cli[@]}" check "$tmp/old.o" "$tmp/new.o" \
  --section xdp \
  --prevail-bin "$tmp/prevail" \
  --equiv-backend k2 \
  --k2-equiv "$K2_EQUIV" \
  --k2-root "$K2_ROOT" \
  --objcopy-bin "$OBJCOPY" \
  --timeout 120 \
  >"$tmp/result.json"

python3 - "$tmp/result.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as result_file:
    payload = json.load(result_file)

assert payload["result"] == "PASS", payload
reasons = [stage["reason"] for stage in payload["stages"]]
assert "k2_equivalence_pass" in reasons, payload
assert "generated_k2_environment" in reasons, payload
PY

cat "$tmp/result.json"
