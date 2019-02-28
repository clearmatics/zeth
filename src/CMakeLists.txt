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

# Set the target of the generated files to ${CMAKE_CURRENT_BINARY_DIR}/proto-src
# Then create this folder and add it to the include directories
set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-src)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR})

# See cmake scripts in the cmake folder
# Generate the grpc and protobuf files and set the result of the generation
# in the given env var (PROTO_SRCS, PROTO_HDRS, GRPC_SRCS, GRPC_HDRS)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS})

include_directories(
  $ENV{ZETH}
  $ENV{ZETH}/src
  libff/common/default_types
)

file(GLOB_RECURSE SOURCES
    circuits/circuits-util.cpp
    libsnark_helpers/libsnark_helpers.cpp
    types/bits.cpp
    util.cpp
)

# Enable Boost for program_options
find_package( Boost REQUIRED COMPONENTS system filesystem )
include_directories( ${Boost_INCLUDE_DIR} )

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories( ${PROJECT_BINARY_DIR} )

# Building the server
add_executable(prover_server
    ${CMAKE_CURRENT_SOURCE_DIR}/prover_server.cc
    ${PROTO_SRCS}
    ${GRPC_SRCS}
    ${SOURCES}
)
target_link_libraries(prover_server
    snark
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    gRPC::grpc++_reflection
    protobuf::libprotobuf
)
target_include_directories(prover_server
    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Tests
# Test the packed_addition used in the joinsplit
add_executable(
    test_addition
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/packed_addition_test.cpp
    ${SOURCES}
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

# Test the joinsplit circuit
add_executable(
    test_prover
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/prover_test.cpp
    ${SOURCES}
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