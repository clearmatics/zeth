# See: http://www.elpauer.org/stuff/learning_cmake.pdf
# For a tutorial of CMake
cmake_minimum_required(VERSION 3.0)

if(APPLE)
  # If custom llvm compilers are available, use them (for openmp
  # support), otherwise disable multicore.
  if(EXISTS "/usr/local/opt/llvm/bin/clang")
    set(CMAKE_C_COMPILER "/usr/local/opt/llvm/bin/clang")
    set(CMAKE_CXX_COMPILER "/usr/local/opt/llvm/bin/clang++")
  endif()
endif()

# Name of the project
# https://cmake.org/cmake/help/v3.0/command/project.html#command:project
# Sets the env vars PROJECT_SOURCE_DIR, and PROJECT_BINARY_DIR
project(zeth)

# Versionning of the project
set (ZETH_VERSION_MAJOR 0)
set (ZETH_VERSION_MINOR 2)

# Configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/zethConfig.h.in"
    "${PROJECT_BINARY_DIR}/zethConfig.h"
)

# Flags and compilation options to chose the type of zksnark
set(
  ZKSNARK # Variable name
  "GROTH16"
  CACHE
  STRING
  "Default snark: one of PGHR13, GROTH16"
)

# Run only fast test (e.g. on CI machine)
option(
  FAST_TESTS_ONLY
  "Include only fast-running tests"
  OFF
)

# Flags and compilation options for use with libsnark
set(
  CURVE # Variable name
  "ALT_BN128" # We use the ALT_BN128 curve here, this is useful to pick the settings related to alt_bn128 in https://github.com/scipr-lab/libff/blob/master/libff/common/default_types/ec_pp.hpp
  CACHE
  STRING
  "Default curve: one of ALT_BN128, BN128, EDWARDS, MNT4, MNT6"
)

set(
  DEPENDS_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}/depends"
  CACHE
  STRING
  "Optionally specify the dependency installation directory relative to the source directory (default: inside dependency folder)"
)

set(
  OPT_FLAGS
  ""
  CACHE
  STRING
  "Override C++ compiler optimization flags"
)

option(
  MULTICORE
  "Enable parallelized execution, using OpenMP"
  ON
)

option(
  WITH_PROCPS
  "Use procps for memory profiling"
  ON
)

option(
  VERBOSE
  "Print internal messages"
  ON
)

option(
  DEBUG
  "Enable debugging mode"
  ON
)

if(APPLE)
  # These must be disabled to make dependencies build on macos
  set(WITH_PROCPS OFF)
  set(WITH_SUPERCOP OFF CACHE BOOL "Build libff with supercop")

  # (Currently) OpenMP only available with custom llvm compilers
  if(${CMAKE_C_COMPILER} MATCHES ".*cc$")
    set(MULTICORE OFF)
  endif()
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "^(Apple)?Clang$")

  # Common compilation flags and warning configuration
  # The CMAKE_CXX_FLAGS variable allows to change the compiler settings
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Wfatal-errors -pthread")

  if("${MULTICORE}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()

   # Default optimizations flags (to override, use -DOPT_FLAGS=...)
  if("${OPT_FLAGS}" STREQUAL "")
    set(OPT_FLAGS "-ggdb3 -O2 -march=native -mtune=native")
  endif()
endif()

add_definitions(-DCURVE_${CURVE})
add_definitions(-DZKSNARK_${ZKSNARK})

enable_testing()

if(${CURVE} STREQUAL "BN128")
  add_definitions(-DBN_SUPPORT_SNARK=1)
endif()

if("${VERBOSE}")
  add_definitions(-DVERBOSE=1)
endif()

if("${MULTICORE}")
  add_definitions(-DMULTICORE=1)
endif()

if("${DEBUG}")
  add_definitions(-DDEBUG=1)
endif()

# Add the given directories to those the compiler uses to search for include files
include_directories(.)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

# Add sub-directories for the build
add_subdirectory(depends)
add_subdirectory(src)
