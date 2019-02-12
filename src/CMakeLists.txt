cmake_minimum_required(VERSION 2.8)

project(zeth)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#### [Begin] gRPC - Protobuf related config ####
# Protobuf
set(_PROTOBUF_PROTOC protoc)
find_library(_PROTOBUF_LIBPROTOBUF NAMES protobuf libprotobuf)

# gRPC
set(GRPC_CPP_PLUGIN grpc_cpp_plugin)
#set(GRPC_CPP_PLUGIN_PATH "which ${grpc_cpp_plugin}")
find_library(_GRPC_GRPCPP_UNSECURE NAMES grpc++ libgrpc++)

# Proto files
get_filename_component(prover_proto "../api/prover-grpc/prover.proto" ABSOLUTE)
get_filename_component(prover_proto_path "${prover_proto}" PATH)

# Generated sources
set(prover_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/prover.pb.cc")
set(prover_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/prover.pb.h")
set(prover_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/prover.grpc.pb.cc")
set(prover_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/prover.grpc.pb.h")
add_custom_command(
      OUTPUT "${prover_proto_srcs}" "${prover_proto_hdrs}" "${prover_grpc_srcs}" "${prover_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${prover_proto_path}"
        #--plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN_PATH}"
        --plugin=protoc-gen-grpc=/usr/local/bin/grpc_cpp_plugin
        "${prover_proto}"
      DEPENDS "${prover_proto}"
)
#### [End] gRPC - Protobuf related config ####

# Include generated *.pb.h files
# and include the rest of the codebase
include_directories(
  #"${CMAKE_CURRENT_BINARY_DIR}"
  "${PROJECT_BINARY_DIR}"
  $ENV{ZETH}
  $ENV{ZETH}/src
  $ENV{ZETH}/src/libnark_helpers
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
include_directories("${PROJECT_BINARY_DIR}")

# Build the targets (prover server)
foreach(_target
  prover_server)
  add_executable(${_target} "${_target}.cc"
    ${prover_proto_srcs}
    ${prover_grpc_srcs}
    ${SOURCES})
  target_link_libraries(${_target}
    LINK_PUBLIC
    snark
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${_GRPC_GRPCPP_UNSECURE}
    ${_PROTOBUF_LIBPROTOBUF})
  target_include_directories(${_target}
    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft)
endforeach()
