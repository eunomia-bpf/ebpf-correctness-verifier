#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ebpf_fixtures import (
    map_lookup_only,
    map_update_then_lookup,
    map_update_then_stack_read,
    packet_byte,
    return_constant,
    return_input_direct,
    return_input_via_stack,
)


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
