Z3_RELEASE_VERSION ?= 4.16.0
Z3_RELEASE_PLATFORM ?= x64-glibc-2.39
Z3_RELEASE_SHA256 ?= 7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e
Z3_RELEASE_DIR ?= .cache/z3-$(Z3_RELEASE_VERSION)
Z3_RELEASE_ARCHIVE := $(Z3_RELEASE_DIR)/z3-$(Z3_RELEASE_VERSION)-$(Z3_RELEASE_PLATFORM).zip
Z3_RELEASE_ROOT := $(Z3_RELEASE_DIR)/z3-$(Z3_RELEASE_VERSION)-$(Z3_RELEASE_PLATFORM)
Z3_RELEASE_URL := https://github.com/Z3Prover/z3/releases/download/z3-$(Z3_RELEASE_VERSION)/z3-$(Z3_RELEASE_VERSION)-$(Z3_RELEASE_PLATFORM).zip

.PHONY: test test-python test-package test-k2-smoke test-k2-z3-release test-examples test-example-k2-xdp test-prevail-smoke

test: test-python test-package test-examples

test-python:
	PYTHONPATH=src python3 -m unittest discover -s tests

test-package:
	mkdir -p build
	rm -rf build/package-smoke-venv
	python3 -m venv --system-site-packages build/package-smoke-venv
	build/package-smoke-venv/bin/python -m pip install --no-build-isolation --no-deps .
	build/package-smoke-venv/bin/ebpf-tv --help >/dev/null
	build/package-smoke-venv/bin/ebpf-tv check --help >/dev/null
	build/package-smoke-venv/bin/ebpf-tv capabilities >/dev/null

test-k2-smoke:
	cmake -S . -B build
	cmake --build build --target k2_ebpf_inst_codegen_test k2_ebpf_equiv -j
	ctest --test-dir build --output-on-failure

$(Z3_RELEASE_ARCHIVE):
	mkdir -p $(Z3_RELEASE_DIR)
	curl -L --fail --silent --show-error -o $@ $(Z3_RELEASE_URL)
	echo "$(Z3_RELEASE_SHA256)  $@" | sha256sum -c -

$(Z3_RELEASE_ROOT): $(Z3_RELEASE_ARCHIVE)
	rm -rf $@
	unzip -q $(Z3_RELEASE_ARCHIVE) -d $(Z3_RELEASE_DIR)

test-k2-z3-release: $(Z3_RELEASE_ROOT)
	rm -rf build-z3-release
	cmake -S . -B build-z3-release \
	  -DZ3_INCLUDE_DIR="$(abspath $(Z3_RELEASE_ROOT))/include" \
	  -DZ3_LIBRARY="$(abspath $(Z3_RELEASE_ROOT))/bin/libz3.so"
	cmake --build build-z3-release --target k2_ebpf_inst_codegen_test k2_ebpf_equiv -j
	ctest --test-dir build-z3-release --output-on-failure
	build-z3-release/k2_ebpf_equiv --version | grep '"full_version": "Z3 $(Z3_RELEASE_VERSION).0"'

test-examples: test-example-k2-xdp

test-example-k2-xdp: test-k2-smoke
	scripts/run-k2-xdp-example.sh >/dev/null

test-prevail-smoke:
	scripts/prevail-smoke.sh
