include_directories(.)

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

# NOTE: dependency include directories use SYSTEM, to prevent the compiler from
# issuing warnings from their headers. See:
# https://foonathan.net/2018/10/cmake-warnings/

# Add the directory containing the Protobuf generated files.
# `PROTO_SRC_DIR` is defined in the parent CMakeLists.txt
include_directories(SYSTEM ${PROTO_SRC_DIR})

# Function defined in the cmake scripts in the cmake folder.
# Generate the protobuf files and set the result of the generation
# in the given env var (PROTO_SRCS, PROTO_HDRS).
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTO_FILES})
set_property(SOURCE ${PROTO_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter -Wno-error"
)

# Enable Boost for program_options
find_package(Boost REQUIRED COMPONENTS system filesystem program_options)
include_directories(${Boost_INCLUDE_DIR})

# libsodium
ExternalProject_Get_Property(libsodium INSTALL_DIR)
set(libsodium_INCLUDE_DIR "${INSTALL_DIR}/include")
set(libsodium_LIBRARY "${INSTALL_DIR}/lib/libsodium.a")

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories(${PROJECT_BINARY_DIR})

string(TOLOWER ${ZKSNARK} ZKSNARK_NAME)

# zeth library
file(
  GLOB_RECURSE
  ZETH_SOURCE
  types/**.?pp types/**.tcc
  circuits/**.?pp circuits/**.tcc
  circuit_wrapper.???
  commitments/**.?pp commitments/**.tcc
  libsnark_helpers/**.?pp libsnark_helpers/**.tcc
  snarks/${ZKSNARK_NAME}/core/**.???
  snarks/${ZKSNARK_NAME}/api/**.???
  snarks_alias.hpp
  include_libsnark.hpp
  util.?pp util.tcc
  util_api.?pp util_api.tcc
  zeth.h
)
add_library(
  zeth

  ${ZETH_SOURCE}
  ${PROTO_SRCS}
)
target_include_directories(
  zeth

  SYSTEM
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${libsodium_INCLUDE_DIR}
)
target_link_libraries(
  zeth

  snark
  ${libsodium_LIBRARY}
)
add_dependencies(zeth libsodium)

## Tests
if ("${IS_ZETH_PARENT}")
  include(CTest)

  # A target which builds all tests, even if they will not be run.
  add_custom_target(build_tests)

  # Function to create test targets, based on the FAST flag:
  #   zeth_test(
  #     <test name> SOURCE <source files> [ARGS <tst arguments>] [FAST])
  function(zeth_test TEST_NAME)
    set(multiValueArgs SOURCE ARGS)
    cmake_parse_arguments(zeth_test "FAST" "" "SOURCE;ARGS" ${ARGN})
    file(GLOB test_src ${zeth_test_SOURCE})

    # Test executable
    add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${test_src})
    target_link_libraries(${TEST_NAME} zeth gtest_main)

    # Add all tests to the 'build_tests' target
    add_dependencies(build_tests ${TEST_NAME})

    if((NOT FAST_TESTS_ONLY) OR zeth_test_FAST)
      add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} ${zeth_test_ARGS})
      add_dependencies(check ${TEST_NAME})
    else()
      message("Skipping slow test ${TEST_NAME}")
    endif()
  endfunction(zeth_test)

  zeth_test(test_addition SOURCE test/packed_addition_test.cpp FAST)
  zeth_test(test_hex_to_field SOURCE test/hex_to_field_test.cpp FAST)
  zeth_test(test_binary_operation SOURCE test/binary_operation_test.cpp FAST)
  zeth_test(test_blake2s SOURCE test/blake2s_test.cpp FAST)
  zeth_test(test_mimc_mp SOURCE test/mimc_mp_test.cpp FAST)
  zeth_test(test_prfs SOURCE test/prfs_test.cpp FAST)
  zeth_test(test_commitments SOURCE test/commitments_test.cpp FAST)
  zeth_test(test_merkle_tree SOURCE test/merkle_tree_test.cpp FAST)
  zeth_test(test_note SOURCE test/note_test.cpp FAST)
  zeth_test(test_prover SOURCE test/prover_test.cpp)

  # Groth16-only tests and MPC
  if(${ZKSNARK} STREQUAL "GROTH16")
    zeth_test(test_simple SOURCE test/simple_test.cpp FAST)
    zeth_test(
      test_powersoftau
      SOURCE test/powersoftau_test.cpp
      ARGS "${CMAKE_CURRENT_LIST_DIR}/.."
      FAST)
    zeth_test(test_mpc SOURCE test/mpc_*.cpp FAST)
    target_link_libraries(
      test_mpc ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
  endif()

  # Extra dependencies for specific tests
  target_link_libraries(
    test_prover
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
  )
  target_link_libraries(
    test_powersoftau
    ${Boost_FILESYSTEM_LIBRARY}
  )

endif()
