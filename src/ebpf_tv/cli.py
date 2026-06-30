from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"

BPF_ALU64_MOV_K = 0xB7
BPF_EXIT = 0x95


@dataclass
class StageResult:
    name: str
    result: str
    reason: str = ""
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""


@dataclass
class ValidationResult:
    result: str
    stages: list[StageResult]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def run_command(command: list[str], timeout: int) -> StageResult:
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return StageResult(
            name="command",
            result=UNKNOWN,
            reason="tool_not_found",
            command=command,
        )
    except subprocess.TimeoutExpired as exc:
        return StageResult(
            name="command",
            result=UNKNOWN,
            reason="timeout",
            command=command,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )

    return StageResult(
        name="command",
        result=PASS if completed.returncode == 0 else FAIL,
        command=command,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def resolve_tool(tool: str) -> str | None:
    if os.path.sep in tool:
        return tool if os.access(tool, os.X_OK) else None
    return shutil.which(tool)


def run_prevail(
    name: str,
    obj: Path,
    section: str,
    function: str | None,
    prevail_bin: str,
    timeout: int,
) -> StageResult:
    tool = resolve_tool(prevail_bin)
    if tool is None:
        return StageResult(name=name, result=UNKNOWN, reason="prevail_not_found")

    command = [tool, str(obj), section]
    if function:
        command.append(function)

    stage = run_command(command, timeout)
    stage.name = name
    output = f"{stage.stdout}\n{stage.stderr}"

    if "PASS:" in output:
        stage.result = PASS
        stage.reason = "prevail_pass"
    elif "Section not found" in output or "Function not found" in output:
        stage.result = UNKNOWN
        stage.reason = "program_not_found"
    elif stage.exit_code == 0 and (
        "error:" in output or "unmarshaling error" in output or "FAIL" in output
    ):
        stage.result = FAIL
        stage.reason = "prevail_reject"
    elif stage.result == FAIL:
        stage.reason = "prevail_failed"
    elif stage.result == PASS:
        stage.result = UNKNOWN
        stage.reason = "prevail_output_unrecognized"
    return stage


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_identity_equivalence(old: Path, new: Path) -> StageResult:
    if sha256(old) == sha256(new):
        return StageResult(
            name="equivalence",
            result=PASS,
            reason="byte_identical",
        )
    return StageResult(
        name="equivalence",
        result=UNKNOWN,
        reason="non_identical_requires_equivalence_backend",
    )


def run_external_equivalence(
    old: Path,
    new: Path,
    section: str,
    function: str | None,
    command_template: list[str],
    timeout: int,
) -> StageResult:
    replacements = {
        "{old}": str(old),
        "{new}": str(new),
        "{section}": section,
        "{function}": function or "",
    }
    command = [replacements.get(part, part) for part in command_template]
    stage = run_command(command, timeout)
    stage.name = "equivalence"
    if stage.exit_code == 0:
        stage.result = PASS
        stage.reason = "external_equivalence_pass"
    elif stage.exit_code == 1:
        stage.result = FAIL
        stage.reason = "external_equivalence_fail"
    elif stage.exit_code == 2:
        stage.result = UNKNOWN
        stage.reason = "external_equivalence_unknown"
    elif stage.result == FAIL:
        stage.result = UNKNOWN
        stage.reason = "external_equivalence_error"
    return stage


def combine(stages: Iterable[StageResult]) -> str:
    results = [stage.result for stage in stages]
    if FAIL in results:
        return FAIL
    if UNKNOWN in results:
        return UNKNOWN
    return PASS


def raw_bpf_insn(
    opcode: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0
) -> bytes:
    regs = (dst & 0x0F) | ((src & 0x0F) << 4)
    return struct.pack("<BBhi", opcode, regs, off, imm)


def raw_return_constant(value: int) -> bytes:
    return raw_bpf_insn(BPF_ALU64_MOV_K, dst=0, imm=value) + raw_bpf_insn(BPF_EXIT)


def run_k2_equiv(
    k2_equiv: str,
    k2_root: str,
    old: Path,
    new: Path,
    maps: Path,
    desc: Path,
    timeout: int,
) -> StageResult:
    return run_command(
        [
            k2_equiv,
            "--old",
            str(old),
            "--new",
            str(new),
            "--map",
            str(maps),
            "--desc",
            str(desc),
            "--k2-root",
            k2_root,
        ],
        timeout=timeout,
    )


def run_k2_equiv_smoke(
    k2_equiv: str | None, k2_root: str | None, timeout: int
) -> StageResult:
    if not k2_equiv:
        return StageResult(
            name="k2_equiv_smoke",
            result=UNKNOWN,
            reason="k2_equiv_not_configured",
        )
    tool = resolve_tool(k2_equiv)
    if tool is None:
        return StageResult(
            name="k2_equiv_smoke",
            result=UNKNOWN,
            reason="k2_equiv_not_found",
        )
    if not k2_root:
        return StageResult(
            name="k2_equiv_smoke",
            result=UNKNOWN,
            reason="k2_root_not_configured",
        )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        ret0 = tmp_path / "ret0.ins"
        ret0_copy = tmp_path / "ret0-copy.ins"
        ret1 = tmp_path / "ret1.ins"
        maps = tmp_path / "empty.maps"
        desc = tmp_path / "constant.desc"

        ret0.write_bytes(raw_return_constant(0))
        ret0_copy.write_bytes(raw_return_constant(0))
        ret1.write_bytes(raw_return_constant(1))
        maps.write_text("")
        desc.write_text("{ pgm_input_type = 0, }\n{ max_pkt_sz = 0, }\n")

        pass_stage = run_k2_equiv(tool, k2_root, ret0, ret0_copy, maps, desc, timeout)
        fail_stage = run_k2_equiv(tool, k2_root, ret0, ret1, maps, desc, timeout)

    stdout = (
        "PASS case stdout:\n"
        + pass_stage.stdout
        + "\nFAIL case stdout:\n"
        + fail_stage.stdout
    )
    stderr = (
        "PASS case stderr:\n"
        + pass_stage.stderr
        + "\nFAIL case stderr:\n"
        + fail_stage.stderr
    )
    if pass_stage.exit_code == 0 and fail_stage.exit_code == 1:
        return StageResult(
            name="k2_equiv_smoke",
            result=PASS,
            reason="k2_equiv_pass_fail_smoke",
            command=[tool, "--k2-root", k2_root],
            stdout=stdout,
            stderr=stderr,
        )
    return StageResult(
        name="k2_equiv_smoke",
        result=FAIL,
        reason="k2_equiv_smoke_failed",
        command=[tool, "--k2-root", k2_root],
        stdout=stdout,
        stderr=stderr,
    )


def check(args: argparse.Namespace) -> int:
    old = Path(args.old)
    new = Path(args.new)
    stages: list[StageResult] = []

    for label, obj in (("input_old", old), ("input_new", new)):
        if not obj.exists():
            stages.append(StageResult(label, FAIL, "file_not_found"))

    if not stages:
        stages.append(
            run_prevail(
                "prevail_old",
                old,
                args.section,
                args.function,
                args.prevail_bin,
                args.timeout,
            )
        )
        stages.append(
            run_prevail(
                "prevail_new",
                new,
                args.section,
                args.function,
                args.prevail_bin,
                args.timeout,
            )
        )

        if args.equiv_backend == "identity":
            stages.append(run_identity_equivalence(old, new))
        else:
            stages.append(
                run_external_equivalence(
                    old,
                    new,
                    args.section,
                    args.function,
                    args.equiv_command,
                    args.timeout,
                )
            )

    result = ValidationResult(combine(stages), stages)
    if args.output == "json":
        print(result.to_json())
    else:
        print(result.result)
        for stage in result.stages:
            suffix = f" ({stage.reason})" if stage.reason else ""
            print(f"{stage.name}: {stage.result}{suffix}")
    return 0 if result.result == PASS else 1


def selftest(args: argparse.Namespace) -> int:
    stages: list[StageResult] = []
    if args.k2_inst_codegen_test:
        stages.append(
            run_command([args.k2_inst_codegen_test], timeout=args.timeout)
        )
        stages[-1].name = "k2_inst_codegen_test"
        stages[-1].reason = "k2_modern_z3_smoke"
    else:
        stages.append(
            StageResult(
                name="k2_inst_codegen_test",
                result=UNKNOWN,
                reason="k2_inst_codegen_test_not_configured",
            )
        )
    if args.k2_equiv or args.k2_root:
        stages.append(run_k2_equiv_smoke(args.k2_equiv, args.k2_root, args.timeout))
    result = ValidationResult(combine(stages), stages)
    print(result.to_json())
    return 0 if result.result == PASS else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ebpf-tv",
        description="Validate eBPF transformations with PREVAIL and an equivalence backend.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="validate old/new objects")
    check_parser.add_argument("old")
    check_parser.add_argument("new")
    check_parser.add_argument("--section", required=True)
    check_parser.add_argument("--function")
    check_parser.add_argument("--prevail-bin", default="prevail")
    check_parser.add_argument(
        "--equiv-backend",
        choices=["identity", "external"],
        default="identity",
        help="identity is a conservative smoke backend; external uses exit codes 0/1/2 for PASS/FAIL/UNKNOWN.",
    )
    check_parser.add_argument(
        "--equiv-command",
        nargs=argparse.REMAINDER,
        default=[],
        help="external equivalence command; supports {old}, {new}, {section}, {function}",
    )
    check_parser.add_argument("--timeout", type=int, default=30)
    check_parser.add_argument("--output", choices=["text", "json"], default="json")
    check_parser.set_defaults(func=check)

    selftest_parser = subparsers.add_parser("selftest", help="run backend smoke tests")
    selftest_parser.add_argument("--k2-inst-codegen-test")
    selftest_parser.add_argument("--k2-equiv")
    selftest_parser.add_argument("--k2-root")
    selftest_parser.add_argument("--timeout", type=int, default=120)
    selftest_parser.set_defaults(func=selftest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check" and args.equiv_backend == "external" and not args.equiv_command:
        parser.error("--equiv-backend external requires --equiv-command")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
