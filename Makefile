.PHONY: test test-python test-k2-smoke

test: test-python test-k2-smoke

test-python:
	PYTHONPATH=src python3 -m unittest discover -s tests

test-k2-smoke:
	cmake -S . -B build
	cmake --build build --target k2_ebpf_inst_codegen_test k2_ebpf_equiv -j
	ctest --test-dir build --output-on-failure
