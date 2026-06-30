#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

PREVAIL_REPO=${PREVAIL_REPO:-https://github.com/vbpf/prevail.git}
PREVAIL_COMMIT=${PREVAIL_COMMIT:-865b701}
PREVAIL_DIR=${PREVAIL_DIR:-$REPO_ROOT/.cache/prevail}
PREVAIL_BUILD_DIR=${PREVAIL_BUILD_DIR:-$PREVAIL_DIR/build}
JOBS=${JOBS:-2}

clone_or_update_prevail() {
  if [[ ! -d "$PREVAIL_DIR/.git" ]]; then
    mkdir -p "$(dirname -- "$PREVAIL_DIR")"
    git clone --recurse-submodules "$PREVAIL_REPO" "$PREVAIL_DIR"
    git -C "$PREVAIL_DIR" checkout "$PREVAIL_COMMIT"
    return
  fi

  git -C "$PREVAIL_DIR" fetch --recurse-submodules origin
  local current
  current=$(git -C "$PREVAIL_DIR" rev-parse HEAD)
  local wanted
  wanted=$(git -C "$PREVAIL_DIR" rev-parse "$PREVAIL_COMMIT")

  if [[ "$current" != "$wanted" ]]; then
    if ! git -C "$PREVAIL_DIR" diff --quiet || ! git -C "$PREVAIL_DIR" diff --cached --quiet; then
      echo "PREVAIL_DIR is dirty at a different commit: $PREVAIL_DIR" >&2
      echo "Remove it or set PREVAIL_DIR to a fresh directory." >&2
      exit 2
    fi
    git -C "$PREVAIL_DIR" checkout "$PREVAIL_COMMIT"
  fi
}

patch_prevail_cmake() {
  python3 - "$PREVAIL_DIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
path = root / "CMakeLists.txt"
text = path.read_text()
fixed = r'target_compile_definitions(prevail-cli PRIVATE PREVAIL_VERSION_STRING=\\\"${prevail_VERSION_STRING}\\\")'
variants = [
    'target_compile_definitions(prevail-cli PRIVATE PREVAIL_VERSION_STRING="${prevail_VERSION_STRING}")',
    r'target_compile_definitions(prevail-cli PRIVATE PREVAIL_VERSION_STRING=\"${prevail_VERSION_STRING}\")',
]

if fixed in text:
    print(f"PREVAIL CMake compatibility patch already present: {path}")
    raise SystemExit(0)

for variant in variants:
    if variant in text:
        path.write_text(text.replace(variant, fixed))
        print(f"Applied PREVAIL CMake compatibility patch: {path}")
        raise SystemExit(0)

raise SystemExit(f"Could not find PREVAIL_VERSION_STRING definition in {path}")
PY
}

run_prevail_smoke() {
  local run_yaml="$PREVAIL_DIR/bin/run_yaml"
  local prevail="$PREVAIL_DIR/bin/prevail"

  "$run_yaml" "$PREVAIL_DIR/test-data/add.yaml" -q
  "$run_yaml" "$PREVAIL_DIR/test-data/map.yaml" -q

  local object_fixture="$PREVAIL_DIR/ebpf-samples/libbpf-bootstrap/minimal.bpf.o"
  local output_file
  output_file=$(mktemp)
  trap 'rm -f "$output_file"' RETURN

  "$prevail" "$object_fixture" tp/syscalls/sys_enter_write | tee "$output_file"
  grep -q '^PASS:' "$output_file"
}

clone_or_update_prevail
git -C "$PREVAIL_DIR" submodule update --init --recursive
patch_prevail_cmake

cmake -S "$PREVAIL_DIR" -B "$PREVAIL_BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$PREVAIL_BUILD_DIR" --target prevail-cli run_yaml -j "$JOBS"

run_prevail_smoke

echo "PREVAIL smoke passed at $PREVAIL_COMMIT"
