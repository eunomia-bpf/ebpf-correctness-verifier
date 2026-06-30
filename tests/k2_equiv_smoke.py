#!/usr/bin/env python3
from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


BPF_ALU64_ADD_K = 0x07
BPF_ALU64_MOV_K = 0xB7
BPF_ALU64_MOV_X = 0xBF
BPF_CALL = 0x85
BPF_ALU_MOV_X = 0xBC
BPF_EXIT = 0x95
BPF_JMP_JEQ_K = 0x15
BPF_LDDW = 0x18
BPF_LDX_MEM_B = 0x71
BPF_LDX_MEM_W = 0x61
BPF_STX_MEM_B = 0x73
BPF_STX_MEM_W = 0x63

BPF_FUNC_MAP_LOOKUP_ELEM = 1
BPF_FUNC_MAP_UPDATE_ELEM = 2


def raw_insn(opcode: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0) -> bytes:
    regs = (dst & 0x0F) | ((src & 0x0F) << 4)
    return struct.pack("<BBhi", opcode, regs, off, imm)


def return_constant(value: int) -> bytes:
    return raw_insn(BPF_ALU64_MOV_K, dst=0, imm=value) + raw_insn(BPF_EXIT)


def return_input_direct() -> bytes:
    return raw_insn(BPF_ALU_MOV_X, dst=0, src=1) + raw_insn(BPF_EXIT)


def return_input_via_stack() -> bytes:
    return (
        raw_insn(BPF_STX_MEM_W, dst=10, src=1, off=-4)
        + raw_insn(BPF_LDX_MEM_W, dst=0, src=10, off=-4)
        + raw_insn(BPF_EXIT)
    )


def load_map_id(dst: int, map_id: int) -> bytes:
    return raw_insn(BPF_LDDW, dst=dst, src=1, imm=map_id)


def map_update_then_lookup() -> bytes:
    return b"".join(
        [
            raw_insn(BPF_STX_MEM_B, dst=10, src=1, off=-2),
            raw_insn(BPF_ALU64_MOV_K, dst=1, imm=0x11),
            raw_insn(BPF_STX_MEM_B, dst=10, src=1, off=-1),
            load_map_id(dst=1, map_id=0),
            raw_insn(BPF_ALU64_MOV_X, dst=2, src=10),
            raw_insn(BPF_ALU64_ADD_K, dst=2, imm=-1),
            raw_insn(BPF_ALU64_MOV_X, dst=3, src=10),
            raw_insn(BPF_ALU64_ADD_K, dst=3, imm=-2),
            raw_insn(BPF_ALU64_MOV_K, dst=4, imm=0),
            raw_insn(BPF_CALL, imm=BPF_FUNC_MAP_UPDATE_ELEM),
            raw_insn(BPF_CALL, imm=BPF_FUNC_MAP_LOOKUP_ELEM),
            raw_insn(BPF_JMP_JEQ_K, dst=0, off=1, imm=0),
            raw_insn(BPF_LDX_MEM_B, dst=0, src=0),
            raw_insn(BPF_EXIT),
        ]
    )


def map_update_then_stack_read() -> bytes:
    return b"".join(
        [
            raw_insn(BPF_STX_MEM_B, dst=10, src=1, off=-2),
            raw_insn(BPF_ALU64_MOV_K, dst=1, imm=0x11),
            raw_insn(BPF_STX_MEM_B, dst=10, src=1, off=-1),
            load_map_id(dst=1, map_id=0),
            raw_insn(BPF_ALU64_MOV_X, dst=2, src=10),
            raw_insn(BPF_ALU64_ADD_K, dst=2, imm=-1),
            raw_insn(BPF_ALU64_MOV_X, dst=3, src=10),
            raw_insn(BPF_ALU64_ADD_K, dst=3, imm=-2),
            raw_insn(BPF_ALU64_MOV_K, dst=4, imm=0),
            raw_insn(BPF_CALL, imm=BPF_FUNC_MAP_UPDATE_ELEM),
            raw_insn(BPF_LDX_MEM_B, dst=0, src=10, off=-2),
            raw_insn(BPF_EXIT),
        ]
    )


def map_lookup_only() -> bytes:
    return b"".join(
        [
            raw_insn(BPF_ALU64_MOV_K, dst=1, imm=0x11),
            raw_insn(BPF_STX_MEM_B, dst=10, src=1, off=-1),
            load_map_id(dst=1, map_id=0),
            raw_insn(BPF_ALU64_MOV_X, dst=2, src=10),
            raw_insn(BPF_ALU64_ADD_K, dst=2, imm=-1),
            raw_insn(BPF_CALL, imm=BPF_FUNC_MAP_LOOKUP_ELEM),
            raw_insn(BPF_JMP_JEQ_K, dst=0, off=1, imm=0),
            raw_insn(BPF_LDX_MEM_B, dst=0, src=0),
            raw_insn(BPF_EXIT),
        ]
    )


def packet_byte(offset: int) -> bytes:
    return raw_insn(BPF_LDX_MEM_B, dst=0, src=1, off=offset) + raw_insn(BPF_EXIT)


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
        direct = tmp_path / "direct.ins"
        stack = tmp_path / "stack.ins"
        maps = tmp_path / "empty.maps"
        desc = tmp_path / "constant.desc"
        map_update_lookup = tmp_path / "map-update-lookup.ins"
        map_update_stack = tmp_path / "map-update-stack.ins"
        map_lookup = tmp_path / "map-lookup.ins"
        map_meta = tmp_path / "map.maps"
        pkt0 = tmp_path / "pkt0.ins"
        pkt0_copy = tmp_path / "pkt0-copy.ins"
        pkt1 = tmp_path / "pkt1.ins"
        pkt_desc = tmp_path / "packet.desc"

        ret0.write_bytes(return_constant(0))
        ret0_copy.write_bytes(return_constant(0))
        ret1.write_bytes(return_constant(1))
        direct.write_bytes(return_input_direct())
        stack.write_bytes(return_input_via_stack())
        maps.write_text("")
        desc.write_text("{ pgm_input_type = 0, }\n{ max_pkt_sz = 0, }\n")
        map_update_lookup.write_bytes(map_update_then_lookup())
        map_update_stack.write_bytes(map_update_then_stack_read())
        map_lookup.write_bytes(map_lookup_only())
        map_meta.write_text(
            "map0 { type = 1, key_size = 1, value_size = 1, "
            "max_entries = 32, fd = 0 }\n"
        )
        pkt0.write_bytes(packet_byte(0))
        pkt0_copy.write_bytes(packet_byte(0))
        pkt1.write_bytes(packet_byte(1))
        pkt_desc.write_text("{ pgm_input_type = 1, }\n{ max_pkt_sz = 16, }\n")

        code, payload, stderr = run_case(tool, k2_root, ret0, ret0_copy, maps, desc)
        assert code == 0, (code, payload, stderr)
        assert payload["result"] == "PASS", payload

        code, payload, stderr = run_case(tool, k2_root, direct, stack, maps, desc)
        assert code == 0, (code, payload, stderr)
        assert payload["result"] == "PASS", payload

        code, payload, stderr = run_case(tool, k2_root, ret0, ret1, maps, desc)
        assert code == 1, (code, payload, stderr)
        assert payload["result"] == "FAIL", payload

        code, payload, stderr = run_case(
            tool, k2_root, map_update_lookup, map_update_stack, map_meta, desc
        )
        assert code == 0, (code, payload, stderr)
        assert payload["result"] == "PASS", payload

        code, payload, stderr = run_case(
            tool, k2_root, map_update_lookup, map_lookup, map_meta, desc
        )
        assert code == 1, (code, payload, stderr)
        assert payload["result"] == "FAIL", payload

        code, payload, stderr = run_case(tool, k2_root, pkt0, pkt0_copy, maps, pkt_desc)
        assert code == 0, (code, payload, stderr)
        assert payload["result"] == "PASS", payload

        code, payload, stderr = run_case(tool, k2_root, pkt0, pkt1, maps, pkt_desc)
        assert code == 1, (code, payload, stderr)
        assert payload["result"] == "FAIL", payload

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
