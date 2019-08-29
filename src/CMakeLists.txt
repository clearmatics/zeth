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
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

set(PROTOS
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
set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-src)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR})

# See cmake scripts in the cmake folder
# Generate the grpc and protobuf files and set the result of the generation
# in the given env var (PROTO_SRCS, PROTO_HDRS, GRPC_SRCS, GRPC_HDRS)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS_PGHR13} ${PROTOS_GROTH16} ${PROTOS_UTIL} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS_PGHR13} ${PROTOS_GROTH16} ${PROTOS_UTIL} ${PROTOS})

set_property(SOURCE ${PROTO_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
)
set_property(SOURCE ${GRPC_SRCS} PROPERTY
  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
)

include_directories(
  $ENV{ZETH}
  $ENV{ZETH}/src
  libff/common/default_types
)


# Enable Boost for program_options
find_package( Boost REQUIRED COMPONENTS system filesystem )
include_directories( ${Boost_INCLUDE_DIR} )

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories( ${PROJECT_BINARY_DIR} )

# zeth library

file(
  GLOB_RECURSE
  ZETH_SOURCE
  types/**.cpp types/**.hpp types/**.tcc
  circuits/**.cpp circuits/**.hpp circuits/**.tcc circuit-wrapper.???
  commitments/**.?pp commitments/**.tcc
  libsnark_helpers/**.?pp libsnark_helpers/**.tcc
  snarks/**.?pp snarks/**.tcc
  snarks_alias.hpp snarks/**.tcc
  include_libsnark.hpp
  util.?pp util.tcc
  zeth.h
)

add_library(
  zeth
  ${ZETH_SOURCE})
target_include_directories(
  zeth
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
target_link_libraries(
  zeth
  snark)

# Building the server
add_executable(
  prover_server

  prover_server.cc util_api.hpp util_api.cpp util_api.tcc
  ${PROTO_SRCS}
  ${GRPC_SRCS}
)
target_link_libraries(
  prover_server

  zeth
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  gRPC::grpc++_reflection
  protobuf::libprotobuf
)

## Tests
include(CTest)

# A target which builds all tests, even if they will not be run.
add_custom_target(build_tests)

function(zeth_test TEST_NAME TEST_SOURCE IS_FAST_TEST)
  add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${TEST_SOURCE})
  target_link_libraries(${TEST_NAME} zeth gtest_main)

  # Add all tests to the 'build_tests' target
  add_dependencies(build_tests ${TEST_NAME})

  if((NOT FAST_TESTS_ONLY) OR IS_FAST_TEST)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    add_dependencies(check ${TEST_NAME})
  else()
    message("Skipping slow test ${TEST_NAME}")
  endif()
endfunction(zeth_test)

zeth_test(test_simple test/simple_test.cpp TRUE)
zeth_test(test_addition test/packed_addition_test.cpp TRUE)
zeth_test(test_hex_to_field test/hex_to_field_test.cpp TRUE)
zeth_test(test_note test/note_test.cpp TRUE)
zeth_test(test_prfs test/prfs_test.cpp TRUE)
zeth_test(test_commitments test/commitments_test.cpp TRUE)
zeth_test(test_round test/round_test.cpp TRUE)
zeth_test(test_mimc test/mimc_test.cpp TRUE)
zeth_test(test_mimc_mp test/mimc_mp_test.cpp TRUE)
zeth_test(test_merkle_tree test/merkle_tree_test.cpp TRUE)
zeth_test(test_prover test/prover_test.cpp FALSE)

# prover test has extra dependencies
target_link_libraries(
  test_prover
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
)
