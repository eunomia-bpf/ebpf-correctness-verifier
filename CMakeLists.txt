cmake_minimum_required(VERSION 3.20)

project(ebpf_correctness_verifier LANGUAGES CXX)

option(EBPF_TV_BUILD_K2_SMOKE "Build K2-derived eBPF semantics smoke tests" ON)

if (EBPF_TV_BUILD_K2_SMOKE)
  find_path(Z3_INCLUDE_DIR NAMES z3++.h REQUIRED)
  find_library(Z3_LIBRARY NAMES z3 REQUIRED)

  set(K2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/k2-superopt")

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

  enable_testing()
  add_test(NAME k2_ebpf_inst_codegen_test COMMAND k2_ebpf_inst_codegen_test)
endif ()
