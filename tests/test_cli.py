from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHONPATH = str(ROOT / "src")


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH
    return subprocess.run(
        [sys.executable, "-m", "ebpf_tv", *args],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )


def make_executable(path: Path, content: str) -> Path:
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


class CliTests(unittest.TestCase):
    def test_identical_files_pass_with_prevail_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            obj = tmp_path / "prog.o"
            obj.write_bytes(b"same")
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )

            completed = run_cli(
                [
                    "check",
                    str(obj),
                    str(obj),
                    "--section",
                    "xdp",
                    "--prevail-bin",
                    str(prevail),
                ]
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["stages"][-1]["reason"], "byte_identical")

    def test_non_identical_files_are_unknown_without_equivalence_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            old = tmp_path / "old.o"
            new = tmp_path / "new.o"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )

            completed = run_cli(
                [
                    "check",
                    str(old),
                    str(new),
                    "--section",
                    "xdp",
                    "--prevail-bin",
                    str(prevail),
                ]
            )

            self.assertEqual(completed.returncode, 1)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "UNKNOWN")
            self.assertEqual(
                result["stages"][-1]["reason"],
                "non_identical_requires_equivalence_backend",
            )

    def test_prevail_reject_makes_result_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            obj = tmp_path / "prog.o"
            obj.write_bytes(b"same")
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "unmarshaling error at 1: incomplete lddw"
                """,
            )

            completed = run_cli(
                [
                    "check",
                    str(obj),
                    str(obj),
                    "--section",
                    "xdp",
                    "--prevail-bin",
                    str(prevail),
                ]
            )

            self.assertEqual(completed.returncode, 1)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "FAIL")
            self.assertEqual(result["stages"][0]["reason"], "prevail_reject")

    def test_external_equivalence_exit_code_one_is_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            old = tmp_path / "old.o"
            new = tmp_path / "new.o"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )
            equiv = make_executable(
                tmp_path / "equiv",
                """\
                #!/usr/bin/env sh
                exit 1
                """,
            )

            completed = run_cli(
                [
                    "check",
                    str(old),
                    str(new),
                    "--section",
                    "xdp",
                    "--prevail-bin",
                    str(prevail),
                    "--equiv-backend",
                    "external",
                    "--equiv-command",
                    str(equiv),
                    "{old}",
                    "{new}",
                ]
            )

            self.assertEqual(completed.returncode, 1)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "FAIL")
            self.assertEqual(result["stages"][-1]["reason"], "external_equivalence_fail")

    def test_missing_prevail_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            obj = Path(tmp) / "prog.o"
            obj.write_bytes(b"same")

            completed = run_cli(
                [
                    "check",
                    str(obj),
                    str(obj),
                    "--section",
                    "xdp",
                    "--prevail-bin",
                    str(Path(tmp) / "missing-prevail"),
                ]
            )

            self.assertEqual(completed.returncode, 1)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "UNKNOWN")
            self.assertEqual(result["stages"][0]["reason"], "prevail_not_found")

    def test_selftest_runs_configured_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            smoke = make_executable(
                Path(tmp) / "smoke",
                """\
                #!/usr/bin/env sh
                exit 0
                """,
            )

            completed = run_cli(["selftest", "--k2-inst-codegen-test", str(smoke)])

            self.assertEqual(completed.returncode, 0)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["stages"][0]["reason"], "k2_modern_z3_smoke")

    def test_selftest_runs_k2_equiv_pass_fail_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            smoke = make_executable(
                tmp_path / "smoke",
                """\
                #!/usr/bin/env sh
                exit 0
                """,
            )
            k2_equiv = make_executable(
                tmp_path / "k2_equiv",
                """\
                #!/usr/bin/env sh
                while [ "$#" -gt 0 ]; do
                  if [ "$1" = "--new" ]; then
                    shift
                    case "$1" in
                      *ret1.ins) exit 1 ;;
                      *) exit 0 ;;
                    esac
                  fi
                  shift
                done
                exit 2
                """,
            )

            completed = run_cli(
                [
                    "selftest",
                    "--k2-inst-codegen-test",
                    str(smoke),
                    "--k2-equiv",
                    str(k2_equiv),
                    "--k2-root",
                    str(tmp_path),
                ]
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["stages"][1]["reason"], "k2_equiv_pass_fail_smoke")


if __name__ == "__main__":
    unittest.main()
