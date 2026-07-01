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

from ebpf_fixtures import (
    map_lookup_only,
    map_update_then_lookup,
    map_update_then_stack_read,
    packet_byte,
    return_constant,
    return_input_direct,
    return_input_via_stack,
    return_one_via_add,
)


def make_executable(path: Path, content: str) -> Path:
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


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
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "src")
    command = [
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
    ]
    if extra_args:
        command.extend(extra_args)
    return subprocess.run(
        command,
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
        map_update_lookup_raw = tmp_path / "map-update-lookup.ins"
        map_update_stack_raw = tmp_path / "map-update-stack.ins"
        map_lookup_raw = tmp_path / "map-lookup.ins"
        packet0_raw = tmp_path / "packet0.ins"
        packet1_raw = tmp_path / "packet1.ins"
        ret1_patched_o = tmp_path / "ret1-patched.o"
        ret1_add_patched_o = tmp_path / "ret1-add-patched.o"
        direct_patched_o = tmp_path / "direct-patched.o"
        stack_patched_o = tmp_path / "stack-patched.o"
        map_update_lookup_o = tmp_path / "map-update-lookup.o"
        map_update_stack_o = tmp_path / "map-update-stack.o"
        map_lookup_o = tmp_path / "map-lookup.o"
        packet0_o = tmp_path / "packet0.o"
        packet1_o = tmp_path / "packet1.o"
        empty_maps = tmp_path / "empty.maps"
        map_meta = tmp_path / "map.maps"
        constant_desc = tmp_path / "constant.desc"
        packet_desc = tmp_path / "packet.desc"
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
        map_update_lookup_raw.write_bytes(map_update_then_lookup())
        map_update_stack_raw.write_bytes(map_update_then_stack_read())
        map_lookup_raw.write_bytes(map_lookup_only())
        packet0_raw.write_bytes(packet_byte(0))
        packet1_raw.write_bytes(packet_byte(1))
        empty_maps.write_text("")
        map_meta.write_text(
            "map0 { type = 1, key_size = 1, value_size = 1, "
            "max_entries = 32, fd = 0 }\n"
        )
        constant_desc.write_text("{ pgm_input_type = 0, }\n{ max_pkt_sz = 0, }\n")
        packet_desc.write_text("{ pgm_input_type = 1, }\n{ max_pkt_sz = 16, }\n")
        update_section(objcopy, ret1_o, ret1_raw, ret1_patched_o)
        update_section(objcopy, ret1_o, ret1_add_raw, ret1_add_patched_o)
        update_section(objcopy, ret1_o, direct_raw, direct_patched_o)
        update_section(objcopy, ret1_o, stack_raw, stack_patched_o)
        update_section(objcopy, ret1_o, map_update_lookup_raw, map_update_lookup_o)
        update_section(objcopy, ret1_o, map_update_stack_raw, map_update_stack_o)
        update_section(objcopy, ret1_o, map_lookup_raw, map_lookup_o)
        update_section(objcopy, ret1_o, packet0_raw, packet0_o)
        update_section(objcopy, ret1_o, packet1_raw, packet1_o)

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

        map_env = [
            "--k2-map",
            str(map_meta),
            "--k2-desc",
            str(constant_desc),
        ]
        map_rewrite = run_check(
            repo_root,
            map_update_lookup_o,
            map_update_stack_o,
            prevail,
            k2_equiv,
            k2_root,
            map_env,
        )
        assert map_rewrite.returncode == 0, (
            map_rewrite.stdout,
            map_rewrite.stderr,
        )
        map_payload = json.loads(map_rewrite.stdout)
        assert map_payload["result"] == "PASS", map_payload
        assert map_payload["stages"][-1]["reason"] == "k2_equivalence_pass", map_payload

        map_diff = run_check(
            repo_root,
            map_update_lookup_o,
            map_lookup_o,
            prevail,
            k2_equiv,
            k2_root,
            map_env,
        )
        assert map_diff.returncode == 1, (map_diff.stdout, map_diff.stderr)
        map_diff_payload = json.loads(map_diff.stdout)
        assert map_diff_payload["result"] == "FAIL", map_diff_payload
        assert (
            map_diff_payload["stages"][-1]["reason"] == "k2_equivalence_fail"
        ), map_diff_payload

        packet_env = [
            "--k2-map",
            str(empty_maps),
            "--k2-desc",
            str(packet_desc),
        ]
        packet_same = run_check(
            repo_root, packet0_o, packet0_o, prevail, k2_equiv, k2_root, packet_env
        )
        assert packet_same.returncode == 0, (packet_same.stdout, packet_same.stderr)
        packet_same_payload = json.loads(packet_same.stdout)
        assert packet_same_payload["result"] == "PASS", packet_same_payload
        assert (
            packet_same_payload["stages"][-1]["reason"] == "k2_equivalence_pass"
        ), packet_same_payload

        packet_diff = run_check(
            repo_root, packet0_o, packet1_o, prevail, k2_equiv, k2_root, packet_env
        )
        assert packet_diff.returncode == 1, (packet_diff.stdout, packet_diff.stderr)
        packet_diff_payload = json.loads(packet_diff.stdout)
        assert packet_diff_payload["result"] == "FAIL", packet_diff_payload
        assert (
            packet_diff_payload["stages"][-1]["reason"] == "k2_equivalence_fail"
        ), packet_diff_payload

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
