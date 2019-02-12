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
get_filename_component(prover_proto "./prover.proto" ABSOLUTE)
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
  "${CMAKE_CURRENT_BINARY_DIR}"
  $ENV{ZETH}
  $ENV{ZETH}/src
)

# Build the targets (prover server)
foreach(_target
  prover_server)
  add_executable(${_target} "${_target}.cc"
    ${prover_proto_srcs}
    ${prover_grpc_srcs})
    #${zeth_srcs}
  target_link_libraries(${_target}
    ${_GRPC_GRPCPP_UNSECURE}
    ${_PROTOBUF_LIBPROTOBUF})
endforeach()
