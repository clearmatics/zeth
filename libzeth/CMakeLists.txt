include_directories(.)

# GRPC and Protocol Buffers libraries location
# `ldconfig -p | grep libgrpc`
# `ldconfig -p | grep libprotobuf`
# Returns the location of the GRPC and Protocol Buffers libraries
#
# CMAKE_MODULE_PATH: Path used for searching by FIND_XXX(), with appropriate suffixes added.
# See: https://cmake.org/cmake/help/v3.0/variable/CMAKE_PREFIX_PATH.html
list(APPEND CMAKE_PREFIX_PATH "/usr/local/lib" "/usr/lib")

# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

set(PROTOS_PROVER
    $ENV{ZETH_API_DIR}/prover.proto
)

set(PROTOS_UTIL
    $ENV{ZETH_API_DIR}/util.proto
)

set(PROTOS_PGHR13
    $ENV{ZETH_API_DIR}/pghr13_messages.proto
)

set(PROTOS_GROTH16
    $ENV{ZETH_API_DIR}/groth16_messages.proto
)

# Set the target of the generated files to ${CMAKE_CURRENT_BINARY_DIR}/proto-src
# Then create this folder and add it to the include directories
# We create the folder from PROJECT_BINARY_DIR to make sure
# we can generate the proto files and re-use them for
# different targets.
set(PROTO_SRC_DIR ${PROJECT_BINARY_DIR}/proto_src)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR})

# Generating sensibly into a python module requires setting --proto_path to the
# zeth root, and referencing files as 'api/prover.proto' etc.  This requires us
# to tweak the references to the source files.
set(PROTOBUF_IMPORT_DIRS ${PROJECT_SOURCE_DIR})
set(PROTOBUF_PROTO_PATH ${PROJECT_SOURCE_DIR})
set(PROTOBUF_APPEND_DEST_PATH "/api")
set(PROTOBUF_GENERATE_CPP_APPEND_PATH FALSE)
set(GRPC_GENERATE_CPP_APPEND_PATH FALSE)

# See cmake scripts in the cmake folder
# Generate the grpc and protobuf files and set the result of the generation
# in the given env var (PROTO_SRCS, PROTO_HDRS, GRPC_SRCS, GRPC_HDRS)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS_PGHR13} ${PROTOS_GROTH16} ${PROTOS_UTIL} ${PROTOS_PROVER})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS_PGHR13} ${PROTOS_GROTH16} ${PROTOS_UTIL} ${PROTOS_PROVER})

set_property(SOURCE ${PROTO_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
)
set_property(SOURCE ${GRPC_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
)

# Enable Boost for program_options
find_package( Boost REQUIRED COMPONENTS system filesystem program_options )
include_directories( ${Boost_INCLUDE_DIR} )

# libsodium
ExternalProject_Get_Property(libsodium INSTALL_DIR)
set(libsodium_INCLUDE_DIR "${INSTALL_DIR}/include")
set(libsodium_LIBRARY "${INSTALL_DIR}/lib/libsodium.a")

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories( ${PROJECT_BINARY_DIR} )

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
  snarks/**.hpp snarks/**.tcc snarks/${ZKSNARK_NAME}/**.cpp
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

  function(zeth_test TEST_NAME)
    cmake_parse_arguments(zeth_test "FAST" "" "SOURCE" ${ARGN} )
    file(GLOB test_src ${zeth_test_SOURCE})

    # Test executable
    add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${test_src})
    target_link_libraries(${TEST_NAME} zeth gtest_main)

    # Add all tests to the 'build_tests' target
    add_dependencies(build_tests ${TEST_NAME})

    if((NOT FAST_TESTS_ONLY) OR zeth_test_FAST)
      add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
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

  # Old Tests
  # zeth_test(test_sha256 test/sha256_test.cpp TRUE)

  # prover test has extra dependencies
  target_link_libraries(
    test_prover
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
  )

  # Groth16-only tests and MPC
  if(${ZKSNARK} STREQUAL "GROTH16")
    zeth_test(test_simple SOURCE test/simple_test.cpp FAST)
    zeth_test(test_powersoftau SOURCE test/powersoftau_test.cpp FAST)
    zeth_test(test_mpc SOURCE test/mpc_*.cpp FAST)
    target_link_libraries(
      test_mpc ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
  endif()
endif()
