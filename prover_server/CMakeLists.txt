list(APPEND CMAKE_PREFIX_PATH "/usr/local/lib" "/usr/lib")
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
#message( $ENV{ZETH} )
#message( ${CMAKE_CURRENT_BINARY_DIR} )
#message( ${PROJECT_BINARY_DIR} )
#
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
#
## To clean up since these files are already generated
## in the binary dir of the zeth library
#set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto_src)
set(PROTO_SRC_DIR ${PROJECT_BINARY_DIR}/proto_src)
#file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR})
#
## Generating sensibly into a python module requires setting --proto_path to the
## zeth root, and referencing files as 'api/prover.proto' etc.  This requires us
## to tweak the references to the source files.
set(PROTOBUF_IMPORT_DIRS ${PROJECT_SOURCE_DIR})
set(PROTOBUF_PROTO_PATH ${PROJECT_SOURCE_DIR})
set(PROTOBUF_APPEND_DEST_PATH "/api")
set(PROTOBUF_GENERATE_CPP_APPEND_PATH FALSE)
set(GRPC_GENERATE_CPP_APPEND_PATH FALSE)

## See cmake scripts in the cmake folder
## Generate the grpc and protobuf files and set the result of the generation
## in the given env var (PROTO_SRCS, PROTO_HDRS, GRPC_SRCS, GRPC_HDRS)
#protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS_PGHR13} ${PROTOS_GROTH16} ${PROTOS_UTIL} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS_PGHR13} ${PROTOS_GROTH16} ${PROTOS_UTIL} ${PROTOS})

#set_property(SOURCE ${PROTO_SRCS} PROPERTY
#  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
#)
#set_property(SOURCE ${GRPC_SRCS} PROPERTY
#  COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-parameter"
#)

# Enable Boost for program_options
find_package( Boost REQUIRED COMPONENTS system filesystem program_options )
include_directories( ${Boost_INCLUDE_DIR} )

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories( ${PROJECT_BINARY_DIR} )

# prover_server executable
file(
  GLOB_RECURSE
  PROVER_SERVER_SOURCE
  prover_server.cpp
)
add_executable(
  prover_server
  ${PROVER_SERVER_SOURCE}
  ${GRPC_SRCS}
)
target_link_libraries(
  prover_server

  zeth
  ${Boost_SYSTEM_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  gRPC::grpc++_reflection
  protobuf::libprotobuf
)
