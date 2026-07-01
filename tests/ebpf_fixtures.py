from __future__ import annotations

import struct


BPF_ALU64_ADD_K = 0x07
BPF_ALU64_MOV_K = 0xB7
BPF_ALU64_MOV_X = 0xBF
BPF_ALU_MOV_X = 0xBC
BPF_CALL = 0x85
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


def return_one_via_add() -> bytes:
    return (
        raw_insn(BPF_ALU64_MOV_K, dst=0, imm=0)
        + raw_insn(BPF_ALU64_ADD_K, dst=0, imm=1)
        + raw_insn(BPF_EXIT)
    )


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
