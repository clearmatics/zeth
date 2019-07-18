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

include_directories(
  $ENV{ZETH}
  $ENV{ZETH}/src
  libff/common/default_types
)

file(GLOB_RECURSE SOURCES_TEST
    libsnark_helpers/debug_helpers.cpp
    circuits/circuits-util.cpp
    types/bits.cpp
    util.cpp
)

file(GLOB_RECURSE SOURCES
    ${SOURCES_TEST}
    util_api.cpp
)

# Enable Boost for program_options
find_package( Boost REQUIRED COMPONENTS system filesystem )
include_directories( ${Boost_INCLUDE_DIR} )

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories( ${PROJECT_BINARY_DIR} )

# Building the server
add_executable(
    prover_server

    ${CMAKE_CURRENT_SOURCE_DIR}/prover_server.cc
    ${PROTO_SRCS}
    ${GRPC_SRCS}
    ${SOURCES}
)
target_link_libraries(
    prover_server

    snark
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    gRPC::grpc++_reflection
    protobuf::libprotobuf
)
target_include_directories(
    prover_server

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

## Tests
# Test the packed_addition used in the joinsplit
add_executable(
    test_addition
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/packed_addition_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_addition

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_addition

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test the notes circuits
add_executable(
    test_note
    EXCLUDE_FROM_ALL

    test/note_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_note

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_note

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test the prfs circuits
add_executable(
    test_prfs
    EXCLUDE_FROM_ALL

    test/prfs_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_prfs

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_prfs

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test the commitments circuits
add_executable(
    test_commitments
    EXCLUDE_FROM_ALL

    test/commitments_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_commitments

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_commitments

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test the round circuits
add_executable(
    test_round
    EXCLUDE_FROM_ALL

    test/round_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_round

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_round

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test the mimc circuits
add_executable(
    test_mimc
    EXCLUDE_FROM_ALL

    test/mimc_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_mimc

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_mimc

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test the mimc hash circuits
add_executable(
    test_mimc_hash
    EXCLUDE_FROM_ALL

    test/mimc_hash_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_mimc_hash

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_mimc_hash

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test merkle tree circuits
add_executable(
    test_merkle_tree
    EXCLUDE_FROM_ALL

    test/merkle_tree_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_merkle_tree

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_merkle_tree

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Test the joinsplit circuit
add_executable(
    test_prover
    EXCLUDE_FROM_ALL

    test/prover_test.cpp
    ${SOURCES_TEST}
)
target_link_libraries(
    test_prover

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_prover

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

include(CTest)
add_test(
    NAME test_addition
    COMMAND test_addition
)
add_test(
    NAME test_round
    COMMAND test_round
)
add_test(
    NAME test_mimc
    COMMAND test_mimc
)
add_test(
    NAME test_mimc_hash
    COMMAND test_mimc_hash
)
add_test(
    NAME test_note
    COMMAND test_note
)
add_test(
    NAME test_prfs
    COMMAND test_prfs
)
add_test(
    NAME test_commitments
    COMMAND test_commitments
)
add_test(
    NAME test_prover
    COMMAND test_prover
)

# We add the test of the prover as part of the testzeth
add_dependencies(check test_addition)
add_dependencies(check test_round)
add_dependencies(check test_mimc)
add_dependencies(check test_mimc_hash)
add_dependencies(check test_merkle_tree)
add_dependencies(check test_note)
add_dependencies(check test_prfs)
add_dependencies(check test_commitments)
add_dependencies(check test_prover)
