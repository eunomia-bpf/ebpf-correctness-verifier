#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


BPF_ALU64_ADD_K = 0x07
BPF_ALU64_MOV_K = 0xB7
BPF_ALU_MOV_X = 0xBC
BPF_EXIT = 0x95
BPF_LDX_MEM_W = 0x61
BPF_STX_MEM_W = 0x63


def make_executable(path: Path, content: str) -> Path:
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def raw_insn(opcode: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0) -> bytes:
    regs = (dst & 0x0F) | ((src & 0x0F) << 4)
    return (
        opcode.to_bytes(1, "little")
        + regs.to_bytes(1, "little")
        + off.to_bytes(2, "little", signed=True)
        + imm.to_bytes(4, "little", signed=True)
    )


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


def compile_bpf(clang: str, source: Path, output: Path) -> bool:
    completed = subprocess.run(
        [
            clang,
            "-target",
            "bpf",
            "-O2",
            "-g0",
            "-c",
            str(source),
            "-o",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        print("SKIP: clang cannot compile -target bpf on this host")
        print(completed.stderr)
        return False
    return True


def update_section(objcopy: str, base: Path, section_data: Path, output: Path) -> None:
    completed = subprocess.run(
        [objcopy, f"--update-section=xdp={section_data}", str(base), str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)


def run_check(
    repo_root: Path,
    old: Path,
    new: Path,
    prevail: Path,
    k2_equiv: Path,
    k2_root: Path,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "src")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ebpf_tv",
            "check",
            str(old),
            str(new),
            "--section",
            "xdp",
            "--prevail-bin",
            str(prevail),
            "--equiv-backend",
            "k2",
            "--k2-equiv",
            str(k2_equiv),
            "--k2-root",
            str(k2_root),
            "--objcopy-bin",
            "llvm-objcopy",
            "--timeout",
            "120",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        raise SystemExit("usage: k2_cli_integration.py K2_EQUIV K2_ROOT REPO_ROOT")

    k2_equiv = Path(argv[1]).resolve()
    k2_root = Path(argv[2]).resolve()
    repo_root = Path(argv[3]).resolve()

    clang = shutil.which("clang")
    objcopy = shutil.which("llvm-objcopy")
    if clang is None or objcopy is None:
        print("SKIP: clang or llvm-objcopy is unavailable")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        ret0_c = tmp_path / "ret0.c"
        ret1_c = tmp_path / "ret1.c"
        ret0_o = tmp_path / "ret0.o"
        ret1_o = tmp_path / "ret1.o"
        ret1_raw = tmp_path / "ret1.ins"
        ret1_add_raw = tmp_path / "ret1-add.ins"
        direct_raw = tmp_path / "direct.ins"
        stack_raw = tmp_path / "stack.ins"
        ret1_patched_o = tmp_path / "ret1-patched.o"
        ret1_add_patched_o = tmp_path / "ret1-add-patched.o"
        direct_patched_o = tmp_path / "direct-patched.o"
        stack_patched_o = tmp_path / "stack-patched.o"
        prevail = make_executable(
            tmp_path / "prevail",
            """\
            #!/usr/bin/env sh
            echo "PASS: $2/prog"
            """,
        )

        template = """\
        #define SEC(NAME) __attribute__((section(NAME), used))
        SEC("xdp") int prog(void *ctx) { return VALUE; }
        char _license[] SEC("license") = "GPL";
        """
        ret0_c.write_text(template.replace("VALUE", "0"), encoding="utf-8")
        ret1_c.write_text(template.replace("VALUE", "1"), encoding="utf-8")

        if not compile_bpf(clang, ret0_c, ret0_o):
            return 0
        if not compile_bpf(clang, ret1_c, ret1_o):
            return 0

        ret1_raw.write_bytes(return_constant(1))
        ret1_add_raw.write_bytes(return_one_via_add())
        direct_raw.write_bytes(return_input_direct())
        stack_raw.write_bytes(return_input_via_stack())
        update_section(objcopy, ret1_o, ret1_raw, ret1_patched_o)
        update_section(objcopy, ret1_o, ret1_add_raw, ret1_add_patched_o)
        update_section(objcopy, ret1_o, direct_raw, direct_patched_o)
        update_section(objcopy, ret1_o, stack_raw, stack_patched_o)

        same = run_check(repo_root, ret0_o, ret0_o, prevail, k2_equiv, k2_root)
        assert same.returncode == 0, (same.stdout, same.stderr)
        same_payload = json.loads(same.stdout)
        assert same_payload["result"] == "PASS", same_payload
        assert same_payload["stages"][-1]["reason"] == "k2_equivalence_pass", same_payload

        rewrite = run_check(
            repo_root,
            ret1_patched_o,
            ret1_add_patched_o,
            prevail,
            k2_equiv,
            k2_root,
        )
        assert rewrite.returncode == 0, (rewrite.stdout, rewrite.stderr)
        rewrite_payload = json.loads(rewrite.stdout)
        assert rewrite_payload["result"] == "PASS", rewrite_payload
        assert rewrite_payload["stages"][-1]["reason"] == "k2_equivalence_pass", rewrite_payload
        assert rewrite_payload["stages"][-1]["exit_code"] == 0, rewrite_payload

        stack_rewrite = run_check(
            repo_root,
            direct_patched_o,
            stack_patched_o,
            prevail,
            k2_equiv,
            k2_root,
        )
        assert stack_rewrite.returncode == 0, (
            stack_rewrite.stdout,
            stack_rewrite.stderr,
        )
        stack_payload = json.loads(stack_rewrite.stdout)
        assert stack_payload["result"] == "PASS", stack_payload
        assert stack_payload["stages"][-1]["reason"] == "k2_equivalence_pass", stack_payload
        assert stack_payload["stages"][-1]["exit_code"] == 0, stack_payload

        diff = run_check(repo_root, ret0_o, ret1_o, prevail, k2_equiv, k2_root)
        assert diff.returncode == 1, (diff.stdout, diff.stderr)
        diff_payload = json.loads(diff.stdout)
        assert diff_payload["result"] == "FAIL", diff_payload
        assert diff_payload["stages"][-1]["reason"] == "k2_equivalence_fail", diff_payload

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
