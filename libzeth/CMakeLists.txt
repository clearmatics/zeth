include_directories(.)

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

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

# Enable Boost for filesystem
find_package(Boost REQUIRED COMPONENTS system filesystem)
include_directories(${Boost_INCLUDE_DIR})

# libsodium
ExternalProject_Get_Property(libsodium INSTALL_DIR)
set(libsodium_INCLUDE_DIR "${INSTALL_DIR}/include")
set(libsodium_LIBRARY "${INSTALL_DIR}/lib/libsodium.a")

# zeth library
file(
  GLOB_RECURSE
  ZETH_SOURCE

  *.hpp
  core/**.?pp core/**.tcc
  snarks/**.?pp snarks/**.tcc
  serialization/**.?pp serialization/**.tcc
  circuits/**.?pp circuits/**.tcc
  mpc/**.?pp mpc/**.tcc
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

# Tests
if ("${IS_ZETH_PARENT}")
  add_subdirectory(tests)
endif()
