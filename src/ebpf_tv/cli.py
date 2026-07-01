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

from . import __version__


PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"

BPF_ALU64_MOV_K = 0xB7
BPF_EXIT = 0x95
BPF_MAP_DEF_RECORD_SIZE = 20
K2_DEFAULT_PACKET_SIZE = 64

K2_INPUT_TYPES = {
    "constant": 0,
    "pkt": 1,
    "pkt-ptrs": 2,
    "skb": 3,
}
K2_PACKET_INPUT_TYPES = {"pkt", "pkt-ptrs", "skb"}
K2_XDP_SECTION_PREFIXES = ("xdp/", "xdp.")


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


@dataclass(frozen=True)
class K2MapSpec:
    map_type: int
    key_size: int
    value_size: int
    max_entries: int
    map_flags: int = 0

    def to_k2_line(self, index: int) -> str:
        return (
            f"map{index} {{ type = {self.map_type}, key_size = {self.key_size}, "
            f"value_size = {self.value_size}, max_entries = {self.max_entries}, "
            f"fd = {index} }}\n"
        )


def build_capabilities() -> dict[str, object]:
    return {
        "version": __version__,
        "result_model": {
            "values": [PASS, FAIL, UNKNOWN],
            "precedence": [FAIL, UNKNOWN, PASS],
        },
        "pass_rule": [
            "PREVAIL(old) PASS",
            "PREVAIL(new) PASS",
            "equivalence(old, new) PASS",
        ],
        "dependency_policy": {
            "prevail": {
                "mode": "external",
                "interface": "--prevail-bin",
                "default_submodule": False,
            },
            "k2": {
                "mode": "vendored",
                "path": "third_party/k2-superopt",
                "modernization": "root CMake build against system Z3",
            },
            "z3": {
                "mode": "system",
                "package": "libz3-dev",
                "default_submodule": False,
                "upstream_release_smoke": "make test-k2-z3-release",
                "upstream_release_version": "4.16.0",
            },
        },
        "equivalence_backends": {
            "identity": {
                "status": "stable",
                "scope": ["byte-identical object PASS", "non-identical object UNKNOWN"],
            },
            "external": {
                "status": "stable",
                "exit_codes": {"0": PASS, "1": FAIL, "2": UNKNOWN},
            },
            "k2": {
                "status": "experimental-supported-slice",
                "features": [
                    "raw .ins equivalence through k2_ebpf_equiv",
                    "ELF section extraction through llvm-objcopy or objcopy",
                    "legacy SEC(\"maps\") struct bpf_map_def extraction",
                    "explicit K2 .maps and .desc overrides",
                    "generated empty map environment",
                    "XDP section prefix to packet-input desc inference",
                    "constant-input desc generation for unknown sections",
                    "shared old/new K2 environment",
                    "system Z3 library integration",
                    "K2/Z3 provenance reporting through k2_ebpf_equiv --version",
                ],
                "tested_positive_cases": [
                    "byte-identical programs",
                    "ALU rewrite",
                    "stack store/load rewrite",
                    "map update/lookup rewrite",
                    "packet byte read equivalence",
                ],
                "tested_negative_cases": [
                    "different return constants",
                    "map update/lookup counterexample",
                    "legacy map metadata mismatch",
                    "different packet byte offsets",
                ],
            },
        },
        "known_gaps": [
            "BTF .maps extraction",
            "CO-RE relocation modeling",
            "loader-derived program/context metadata",
            "kernel verifier load gate",
            "BPF_PROG_RUN differential execution",
            "helper side effects beyond current K2 fixtures",
            "mutable global equivalence",
            "ringbuf/perf-event output sinks",
            "atomicity-preservation structural checks",
            "counterexample minimization",
        ],
        "docs": {
            "dependency_policy": "docs/dependency-policy.md",
            "backend_contract": "docs/backend-contract.md",
            "test_plan": "docs/test-plan.md",
        },
    }


def capabilities(args: argparse.Namespace) -> int:
    data = build_capabilities()
    if args.output == "json":
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        dependencies = data["dependency_policy"]
        backends = data["equivalence_backends"]
        print(f"ebpf-tv {data['version']}")
        print("PASS rule: PREVAIL(old) PASS AND PREVAIL(new) PASS AND equivalence PASS")
        print(
            "Dependencies: "
            f"PREVAIL={dependencies['prevail']['mode']}, "
            f"K2={dependencies['k2']['mode']}, "
            f"Z3={dependencies['z3']['mode']}"
        )
        print("Equivalence backends:")
        for name, backend in backends.items():
            print(f"  {name}: {backend['status']}")
        print("Known gaps:")
        for gap in data["known_gaps"]:
            print(f"  - {gap}")
    return 0


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


def resolve_objcopy(tool: str) -> str | None:
    if tool != "auto":
        return resolve_tool(tool)
    return shutil.which("llvm-objcopy") or shutil.which("objcopy")


def infer_k2_input_type(section: str) -> str:
    normalized = section.lower()
    if normalized == "xdp" or normalized.startswith(K2_XDP_SECTION_PREFIXES):
        return "pkt"
    return "constant"


def resolve_k2_desc_inputs(
    section: str,
    requested_input_type: str,
    requested_max_pkt_size: int,
) -> tuple[str, int]:
    input_type = (
        infer_k2_input_type(section)
        if requested_input_type == "auto"
        else requested_input_type
    )
    max_pkt_size = requested_max_pkt_size
    if input_type in K2_PACKET_INPUT_TYPES and max_pkt_size <= 0:
        max_pkt_size = K2_DEFAULT_PACKET_SIZE
    return input_type, max_pkt_size


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


def run_objcopy_dump_section(
    name: str,
    obj: Path,
    section: str,
    output: Path,
    objcopy_bin: str,
    timeout: int,
) -> StageResult:
    tool = resolve_objcopy(objcopy_bin)
    if tool is None:
        return StageResult(name=name, result=UNKNOWN, reason="objcopy_not_found")

    stage = run_command(
        [tool, f"--dump-section={section}={output}", str(obj)],
        timeout,
    )
    stage.name = name
    if stage.exit_code == 0 and output.exists() and output.stat().st_size > 0:
        stage.result = PASS
        stage.reason = "section_extracted"
    elif stage.exit_code == 0:
        stage.result = UNKNOWN
        stage.reason = "empty_or_missing_section_dump"
    else:
        stage.result = UNKNOWN
        stage.reason = "section_extract_failed"
    return stage


def parse_legacy_map_section(data: bytes) -> list[K2MapSpec]:
    if not data:
        return []
    if len(data) % BPF_MAP_DEF_RECORD_SIZE != 0:
        raise ValueError(
            f"legacy maps section size {len(data)} is not a multiple of "
            f"{BPF_MAP_DEF_RECORD_SIZE}"
        )

    maps: list[K2MapSpec] = []
    for offset in range(0, len(data), BPF_MAP_DEF_RECORD_SIZE):
        map_type, key_size, value_size, max_entries, map_flags = struct.unpack_from(
            "<IIIII", data, offset
        )
        if map_type == 0 or key_size == 0 or value_size == 0 or max_entries == 0:
            raise ValueError(f"legacy map record at offset {offset} has zero fields")
        maps.append(K2MapSpec(map_type, key_size, value_size, max_entries, map_flags))
    return maps


def write_k2_maps(path: Path, maps: list[K2MapSpec]) -> None:
    path.write_text("".join(spec.to_k2_line(index) for index, spec in enumerate(maps)))


def run_legacy_map_extract(
    name: str,
    obj: Path,
    output: Path,
    objcopy_bin: str,
    timeout: int,
) -> tuple[StageResult, list[K2MapSpec]]:
    tool = resolve_objcopy(objcopy_bin)
    if tool is None:
        return (
            StageResult(name=name, result=UNKNOWN, reason="objcopy_not_found"),
            [],
        )

    stage = run_command(
        [tool, f"--dump-section=maps={output}", str(obj)],
        timeout,
    )
    stage.name = name
    if stage.exit_code != 0:
        stage.result = PASS
        stage.reason = "legacy_maps_not_found"
        return stage, []
    if not output.exists():
        stage.result = UNKNOWN
        stage.reason = "legacy_maps_dump_missing"
        return stage, []

    try:
        maps = parse_legacy_map_section(output.read_bytes())
    except ValueError as error:
        stage.result = UNKNOWN
        stage.reason = "legacy_maps_malformed"
        stage.stderr = f"{stage.stderr}\n{error}".strip()
        return stage, []

    stage.result = PASS
    stage.reason = "legacy_maps_extracted" if maps else "legacy_maps_empty"
    stage.stdout = "".join(spec.to_k2_line(index) for index, spec in enumerate(maps))
    return stage, maps


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


def run_k2_elf_equivalence(
    old: Path,
    new: Path,
    section: str,
    k2_equiv: str,
    k2_root: str,
    k2_map: str | None,
    k2_desc: str | None,
    k2_input_type: str,
    k2_max_pkt_size: int,
    objcopy_bin: str,
    timeout: int,
) -> list[StageResult]:
    stages: list[StageResult] = []
    tool = resolve_tool(k2_equiv)
    if tool is None:
        return [
            StageResult(
                name="equivalence",
                result=UNKNOWN,
                reason="k2_equiv_not_found",
            )
        ]

    required_paths = [("input_k2_root", Path(k2_root))]
    if k2_map:
        required_paths.append(("input_k2_map", Path(k2_map)))
    if k2_desc:
        required_paths.append(("input_k2_desc", Path(k2_desc)))

    for name, path in required_paths:
        if not path.exists():
            stages.append(StageResult(name=name, result=FAIL, reason="file_not_found"))

    if stages:
        return stages

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        old_insns = tmp_path / "old.ins"
        new_insns = tmp_path / "new.ins"
        map_path = Path(k2_map) if k2_map else tmp_path / "generated.maps"
        desc_path = Path(k2_desc) if k2_desc else tmp_path / "generated.desc"
        if not k2_map:
            old_maps_stage, old_maps = run_legacy_map_extract(
                "k2_maps_old",
                old,
                tmp_path / "old.maps.raw",
                objcopy_bin,
                timeout,
            )
            new_maps_stage, new_maps = run_legacy_map_extract(
                "k2_maps_new",
                new,
                tmp_path / "new.maps.raw",
                objcopy_bin,
                timeout,
            )
            stages.extend([old_maps_stage, new_maps_stage])
            if combine(stages) != PASS:
                return stages
            if old_maps != new_maps:
                stages.append(
                    StageResult(
                        name="k2_map_env",
                        result=FAIL,
                        reason="legacy_map_metadata_mismatch",
                    )
                )
                return stages
            write_k2_maps(map_path, old_maps)
        if not k2_desc:
            input_type_name, max_pkt_size = resolve_k2_desc_inputs(
                section,
                k2_input_type,
                k2_max_pkt_size,
            )
            input_type = K2_INPUT_TYPES[input_type_name]
            desc_path.write_text(
                f"{{ pgm_input_type = {input_type}, }}\n"
                f"{{ max_pkt_sz = {max_pkt_size}, }}\n"
            )
        if not k2_map or not k2_desc:
            stages.append(
                StageResult(
                    name="k2_env",
                    result=PASS,
                    reason="generated_k2_environment",
                )
            )
        stages.append(
            run_objcopy_dump_section(
                "extract_old",
                old,
                section,
                old_insns,
                objcopy_bin,
                timeout,
            )
        )
        stages.append(
            run_objcopy_dump_section(
                "extract_new",
                new,
                section,
                new_insns,
                objcopy_bin,
                timeout,
            )
        )

        if combine(stages) == PASS:
            stage = run_k2_equiv(
                tool,
                k2_root,
                old_insns,
                new_insns,
                map_path,
                desc_path,
                timeout,
            )
            stage.name = "equivalence"
            if stage.exit_code == 0:
                stage.result = PASS
                stage.reason = "k2_equivalence_pass"
            elif stage.exit_code == 1:
                stage.result = FAIL
                stage.reason = "k2_equivalence_fail"
            elif stage.exit_code == 2:
                stage.result = UNKNOWN
                stage.reason = "k2_equivalence_unknown"
            elif stage.result == FAIL:
                stage.result = UNKNOWN
                stage.reason = "k2_equivalence_error"
            stages.append(stage)

    return stages


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
        elif args.equiv_backend == "external":
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
        else:
            stages.extend(
                run_k2_elf_equivalence(
                    old,
                    new,
                    args.section,
                    args.k2_equiv,
                    args.k2_root,
                    args.k2_map,
                    args.k2_desc,
                    args.k2_input_type,
                    args.k2_max_pkt_size,
                    args.objcopy_bin,
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
        choices=["identity", "external", "k2"],
        default="identity",
        help="identity is conservative; external and k2 use exit codes 0/1/2 for PASS/FAIL/UNKNOWN.",
    )
    check_parser.add_argument(
        "--equiv-command",
        nargs=argparse.REMAINDER,
        default=[],
        help="external equivalence command; supports {old}, {new}, {section}, {function}",
    )
    check_parser.add_argument("--k2-equiv", default="k2_ebpf_equiv")
    check_parser.add_argument("--k2-root")
    check_parser.add_argument(
        "--k2-map",
        help=(
            "K2 map metadata file; omitted means auto-extract legacy ELF "
            "maps when present, otherwise generate an empty map environment"
        ),
    )
    check_parser.add_argument(
        "--k2-desc",
        help="K2 program description file; omitted means generate one from --k2-input-type and --k2-max-pkt-size",
    )
    check_parser.add_argument(
        "--k2-input-type",
        choices=sorted([*K2_INPUT_TYPES, "auto"]),
        default="auto",
        help=(
            "generated K2 desc input type when --k2-desc is omitted; "
            "auto infers supported section prefixes"
        ),
    )
    check_parser.add_argument(
        "--k2-max-pkt-size",
        type=int,
        default=0,
        help=(
            "generated K2 desc max packet size when --k2-desc is omitted; "
            "packet-like inputs use 64 when this is zero"
        ),
    )
    check_parser.add_argument(
        "--objcopy-bin",
        default="auto",
        help="tool used to dump ELF sections for K2; 'auto' prefers llvm-objcopy then objcopy",
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

    capabilities_parser = subparsers.add_parser(
        "capabilities",
        help="print the supported dependency, backend, and test-coverage slice",
    )
    capabilities_parser.add_argument("--output", choices=["text", "json"], default="json")
    capabilities_parser.set_defaults(func=capabilities)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check" and args.equiv_backend == "external" and not args.equiv_command:
        parser.error("--equiv-backend external requires --equiv-command")
    if args.command == "check" and args.equiv_backend == "k2":
        if not args.k2_root:
            parser.error("--equiv-backend k2 requires --k2-root")
        if args.k2_max_pkt_size < 0:
            parser.error("--k2-max-pkt-size must be non-negative")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
