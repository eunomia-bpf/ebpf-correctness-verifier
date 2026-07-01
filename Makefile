.PHONY: test test-python test-package test-k2-smoke test-examples test-example-k2-xdp test-prevail-smoke

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

test-k2-smoke:
	cmake -S . -B build
	cmake --build build --target k2_ebpf_inst_codegen_test k2_ebpf_equiv -j
	ctest --test-dir build --output-on-failure

test-examples: test-example-k2-xdp

test-example-k2-xdp: test-k2-smoke
	scripts/run-k2-xdp-example.sh >/dev/null

test-prevail-smoke:
	scripts/prevail-smoke.sh
