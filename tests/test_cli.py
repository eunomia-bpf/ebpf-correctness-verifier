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

from ebpf_fixtures import legacy_map_def


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

    def test_k2_equivalence_backend_generates_default_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            old = tmp_path / "old.o"
            old.write_bytes(b"old-elf")
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )
            objcopy = make_executable(
                tmp_path / "objcopy",
                """\
                #!/usr/bin/env sh
                spec="${1#--dump-section=}"
                section="${spec%%=*}"
                out="${spec#*=}"
                [ "$section" = "maps" ] && exit 1
                case "$2" in
                  *old.o) printf old > "$out" ;;
                  *new.o) printf new > "$out" ;;
                  *) exit 1 ;;
                esac
                """,
            )
            k2_equiv = make_executable(
                tmp_path / "k2_equiv",
                """\
                #!/usr/bin/env sh
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --old) shift; old="$1" ;;
                    --new) shift; new="$1" ;;
                    --map) shift; map="$1" ;;
                    --desc) shift; desc="$1" ;;
                  esac
                  shift
                done
                [ ! -s "$map" ] || exit 2
                grep -q "pgm_input_type = 0" "$desc" || exit 2
                grep -q "max_pkt_sz = 0" "$desc" || exit 2
                cmp -s "$old" "$new"
                """,
            )

            completed = run_cli(
                [
                    "check",
                    str(old),
                    str(old),
                    "--section",
                    "xdp",
                    "--prevail-bin",
                    str(prevail),
                    "--equiv-backend",
                    "k2",
                    "--k2-equiv",
                    str(k2_equiv),
                    "--k2-root",
                    str(tmp_path),
                    "--objcopy-bin",
                    str(objcopy),
                ]
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "PASS")
            self.assertIn(
                ("k2_env", "generated_k2_environment"),
                [(stage["name"], stage["reason"]) for stage in result["stages"]],
            )
            self.assertEqual(result["stages"][-1]["reason"], "k2_equivalence_pass")

    def test_k2_equivalence_backend_generates_packet_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            obj = tmp_path / "prog.o"
            obj.write_bytes(b"elf")
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )
            objcopy = make_executable(
                tmp_path / "objcopy",
                """\
                #!/usr/bin/env sh
                spec="${1#--dump-section=}"
                section="${spec%%=*}"
                out="${spec#*=}"
                [ "$section" = "maps" ] && exit 1
                printf section > "$out"
                """,
            )
            k2_equiv = make_executable(
                tmp_path / "k2_equiv",
                """\
                #!/usr/bin/env sh
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --map) shift; map="$1" ;;
                    --desc) shift; desc="$1" ;;
                  esac
                  shift
                done
                [ ! -s "$map" ] || exit 2
                grep -q "pgm_input_type = 1" "$desc" || exit 2
                grep -q "max_pkt_sz = 16" "$desc" || exit 2
                exit 0
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
                    "--equiv-backend",
                    "k2",
                    "--k2-equiv",
                    str(k2_equiv),
                    "--k2-root",
                    str(tmp_path),
                    "--k2-input-type",
                    "pkt",
                    "--k2-max-pkt-size",
                    "16",
                    "--objcopy-bin",
                    str(objcopy),
                ]
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["stages"][-1]["reason"], "k2_equivalence_pass")

    def test_k2_equivalence_backend_auto_extracts_legacy_maps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            old = tmp_path / "old.o"
            new = tmp_path / "new.o"
            old.write_bytes(b"old-elf")
            new.write_bytes(b"new-elf")
            map_hex = legacy_map_def(key_size=4, value_size=8, max_entries=16).hex()
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )
            objcopy = make_executable(
                tmp_path / "objcopy",
                f"""\
                #!/usr/bin/env python3
                from pathlib import Path
                import sys

                spec = sys.argv[1][len("--dump-section="):]
                section, output = spec.split("=", 1)
                if section == "maps":
                    Path(output).write_bytes(bytes.fromhex("{map_hex}"))
                elif section == "xdp":
                    Path(output).write_bytes(b"section")
                else:
                    raise SystemExit(1)
                """,
            )
            k2_equiv = make_executable(
                tmp_path / "k2_equiv",
                """\
                #!/usr/bin/env sh
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --map) shift; map="$1" ;;
                    --desc) shift; desc="$1" ;;
                  esac
                  shift
                done
                grep -q "key_size = 4" "$map" || exit 2
                grep -q "value_size = 8" "$map" || exit 2
                grep -q "max_entries = 16" "$map" || exit 2
                grep -q "pgm_input_type = 0" "$desc" || exit 2
                exit 0
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
                    "k2",
                    "--k2-equiv",
                    str(k2_equiv),
                    "--k2-root",
                    str(tmp_path),
                    "--objcopy-bin",
                    str(objcopy),
                ]
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "PASS")
            self.assertIn(
                ("k2_maps_old", "legacy_maps_extracted"),
                [(stage["name"], stage["reason"]) for stage in result["stages"]],
            )
            self.assertEqual(result["stages"][-1]["reason"], "k2_equivalence_pass")

    def test_k2_equivalence_backend_rejects_legacy_map_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            old = tmp_path / "old.o"
            new = tmp_path / "new.o"
            old.write_bytes(b"old-elf")
            new.write_bytes(b"new-elf")
            old_map_hex = legacy_map_def(key_size=4).hex()
            new_map_hex = legacy_map_def(key_size=8).hex()
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )
            objcopy = make_executable(
                tmp_path / "objcopy",
                f"""\
                #!/usr/bin/env python3
                from pathlib import Path
                import sys

                spec = sys.argv[1][len("--dump-section="):]
                section, output = spec.split("=", 1)
                obj = Path(sys.argv[2]).name
                if section == "maps":
                    if obj == "old.o":
                        Path(output).write_bytes(bytes.fromhex("{old_map_hex}"))
                    else:
                        Path(output).write_bytes(bytes.fromhex("{new_map_hex}"))
                elif section == "xdp":
                    Path(output).write_bytes(b"section")
                else:
                    raise SystemExit(1)
                """,
            )
            k2_equiv = make_executable(
                tmp_path / "k2_equiv",
                """\
                #!/usr/bin/env sh
                exit 0
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
                    "k2",
                    "--k2-equiv",
                    str(k2_equiv),
                    "--k2-root",
                    str(tmp_path),
                    "--objcopy-bin",
                    str(objcopy),
                ]
            )

            self.assertEqual(completed.returncode, 1)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "FAIL")
            self.assertIn(
                ("k2_map_env", "legacy_map_metadata_mismatch"),
                [(stage["name"], stage["reason"]) for stage in result["stages"]],
            )

    def test_k2_equivalence_backend_fails_different_extracted_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            old = tmp_path / "old.o"
            new = tmp_path / "new.o"
            old.write_bytes(b"old-elf")
            new.write_bytes(b"new-elf")
            maps = tmp_path / "empty.maps"
            desc = tmp_path / "constant.desc"
            maps.write_text("")
            desc.write_text("{ pgm_input_type = 0, }\n{ max_pkt_sz = 0, }\n")
            prevail = make_executable(
                tmp_path / "prevail",
                """\
                #!/usr/bin/env sh
                echo "PASS: $2/func"
                """,
            )
            objcopy = make_executable(
                tmp_path / "objcopy",
                """\
                #!/usr/bin/env sh
                spec="${1#--dump-section=}"
                out="${spec#*=}"
                case "$2" in
                  *old.o) printf old > "$out" ;;
                  *new.o) printf new > "$out" ;;
                  *) exit 1 ;;
                esac
                """,
            )
            k2_equiv = make_executable(
                tmp_path / "k2_equiv",
                """\
                #!/usr/bin/env sh
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --old) shift; old="$1" ;;
                    --new) shift; new="$1" ;;
                  esac
                  shift
                done
                cmp -s "$old" "$new"
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
                    "k2",
                    "--k2-equiv",
                    str(k2_equiv),
                    "--k2-root",
                    str(tmp_path),
                    "--k2-map",
                    str(maps),
                    "--k2-desc",
                    str(desc),
                    "--objcopy-bin",
                    str(objcopy),
                ]
            )

            self.assertEqual(completed.returncode, 1)
            result = json.loads(completed.stdout)
            self.assertEqual(result["result"], "FAIL")
            self.assertEqual(result["stages"][-1]["reason"], "k2_equivalence_fail")

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
