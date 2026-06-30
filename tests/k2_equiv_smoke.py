#!/usr/bin/env python3
from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


BPF_ALU64_MOV_K = 0xB7
BPF_EXIT = 0x95


def raw_insn(opcode: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0) -> bytes:
    regs = (dst & 0x0F) | ((src & 0x0F) << 4)
    return struct.pack("<BBhi", opcode, regs, off, imm)


def return_constant(value: int) -> bytes:
    return raw_insn(BPF_ALU64_MOV_K, dst=0, imm=value) + raw_insn(BPF_EXIT)


def run_case(
    tool: Path,
    k2_root: Path,
    old_path: Path,
    new_path: Path,
    map_path: Path,
    desc_path: Path,
) -> tuple[int, dict[str, object], str]:
    completed = subprocess.run(
        [
            str(tool),
            "--old",
            str(old_path),
            "--new",
            str(new_path),
            "--map",
            str(map_path),
            "--desc",
            str(desc_path),
            "--k2-root",
            str(k2_root),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"tool did not emit JSON on stdout\nstdout={completed.stdout}\nstderr={completed.stderr}"
        ) from exc
    return completed.returncode, payload, completed.stderr


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit("usage: k2_equiv_smoke.py K2_EQUIV K2_ROOT")

    tool = Path(argv[1]).resolve()
    k2_root = Path(argv[2]).resolve()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        ret0 = tmp_path / "ret0.ins"
        ret0_copy = tmp_path / "ret0-copy.ins"
        ret1 = tmp_path / "ret1.ins"
        maps = tmp_path / "empty.maps"
        desc = tmp_path / "constant.desc"

        ret0.write_bytes(return_constant(0))
        ret0_copy.write_bytes(return_constant(0))
        ret1.write_bytes(return_constant(1))
        maps.write_text("")
        desc.write_text("{ pgm_input_type = 0, }\n{ max_pkt_sz = 0, }\n")

        code, payload, stderr = run_case(tool, k2_root, ret0, ret0_copy, maps, desc)
        assert code == 0, (code, payload, stderr)
        assert payload["result"] == "PASS", payload

        code, payload, stderr = run_case(tool, k2_root, ret0, ret1, maps, desc)
        assert code == 1, (code, payload, stderr)
        assert payload["result"] == "FAIL", payload

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
