cmake_minimum_required(VERSION 3.20)

project(ebpf_correctness_verifier LANGUAGES CXX)

option(EBPF_TV_BUILD_K2_SMOKE "Build K2-derived eBPF semantics smoke tests" ON)

if (EBPF_TV_BUILD_K2_SMOKE)
  find_path(Z3_INCLUDE_DIR NAMES z3++.h REQUIRED)
  find_library(Z3_LIBRARY NAMES z3 REQUIRED)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)

  set(K2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/k2-superopt")
  set(K2_EBPF_CORE_SOURCES
    "${K2_DIR}/src/utils.cc"
    "${K2_DIR}/src/inout.cc"
    "${K2_DIR}/src/isa/inst.cc"
    "${K2_DIR}/src/isa/inst_var.cc"
    "${K2_DIR}/src/isa/prog.cc"
    "${K2_DIR}/src/isa/ebpf/inst.cc"
    "${K2_DIR}/src/isa/ebpf/inst_var.cc"
    "${K2_DIR}/src/isa/ebpf/inst_codegen.cc"
    "${K2_DIR}/src/isa/ebpf/canonicalize.cc"
    "${K2_DIR}/src/verify/cfg.cc"
    "${K2_DIR}/src/verify/smt_prog.cc"
    "${K2_DIR}/src/verify/validator.cc"
    "${K2_DIR}/src/verify/z3client.cc"
  )

  add_executable(k2_ebpf_inst_codegen_test
    "${K2_DIR}/src/isa/ebpf/inst_codegen_test.cc"
    "${K2_DIR}/src/utils.cc"
    "${K2_DIR}/src/isa/ebpf/inst_codegen.cc"
    "${K2_DIR}/src/isa/inst.cc"
    "${K2_DIR}/src/isa/inst_var.cc"
    "${K2_DIR}/src/isa/ebpf/inst_var.cc"
  )
  target_compile_features(k2_ebpf_inst_codegen_test PRIVATE cxx_std_17)
  target_compile_definitions(k2_ebpf_inst_codegen_test PRIVATE ISA_EBPF)
  target_include_directories(k2_ebpf_inst_codegen_test PRIVATE
    "${K2_DIR}"
    "${Z3_INCLUDE_DIR}"
  )
  target_link_libraries(k2_ebpf_inst_codegen_test PRIVATE "${Z3_LIBRARY}")

  add_executable(k2_ebpf_equiv
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/k2_equiv.cc"
    "${K2_DIR}/measure/benchmark_ebpf.cc"
    ${K2_EBPF_CORE_SOURCES}
  )
  target_compile_features(k2_ebpf_equiv PRIVATE cxx_std_17)
  target_compile_definitions(k2_ebpf_equiv PRIVATE ISA_EBPF)
  target_include_directories(k2_ebpf_equiv PRIVATE
    "${K2_DIR}"
    "${Z3_INCLUDE_DIR}"
  )
  target_link_libraries(k2_ebpf_equiv PRIVATE "${Z3_LIBRARY}")

  enable_testing()
  add_test(NAME k2_ebpf_inst_codegen_test COMMAND k2_ebpf_inst_codegen_test)
  add_test(NAME k2_ebpf_equiv_smoke
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/k2_equiv_smoke.py"
      "$<TARGET_FILE:k2_ebpf_equiv>"
      "${K2_DIR}"
  )
endif ()
