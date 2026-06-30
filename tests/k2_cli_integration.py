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


def run_check(
    repo_root: Path,
    old: Path,
    new: Path,
    prevail: Path,
    k2_equiv: Path,
    k2_root: Path,
    maps: Path,
    desc: Path,
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
            "--k2-map",
            str(maps),
            "--k2-desc",
            str(desc),
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
        maps = tmp_path / "empty.maps"
        desc = tmp_path / "constant.desc"
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
        maps.write_text("", encoding="utf-8")
        desc.write_text(
            "{ pgm_input_type = 0, }\n{ max_pkt_sz = 0, }\n",
            encoding="utf-8",
        )

        if not compile_bpf(clang, ret0_c, ret0_o):
            return 0
        if not compile_bpf(clang, ret1_c, ret1_o):
            return 0

        same = run_check(
            repo_root, ret0_o, ret0_o, prevail, k2_equiv, k2_root, maps, desc
        )
        assert same.returncode == 0, (same.stdout, same.stderr)
        same_payload = json.loads(same.stdout)
        assert same_payload["result"] == "PASS", same_payload
        assert same_payload["stages"][-1]["reason"] == "k2_equivalence_pass", same_payload

        diff = run_check(
            repo_root, ret0_o, ret1_o, prevail, k2_equiv, k2_root, maps, desc
        )
        assert diff.returncode == 1, (diff.stdout, diff.stderr)
        diff_payload = json.loads(diff.stdout)
        assert diff_payload["result"] == "FAIL", diff_payload
        assert diff_payload["stages"][-1]["reason"] == "k2_equivalence_fail", diff_payload

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
