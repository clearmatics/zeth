# See: http://www.elpauer.org/stuff/learning_cmake.pdf
# For a tutorial of CMake
cmake_minimum_required(VERSION 2.8)

# Name of the project
project(zeroEth)

# The set instruction sets environment variables
# Note: If this environment variable already exist in the cache, it is shadowed by the set value here
# We use the value CACHE in order to keep the value cached (and avoid shadowing)
set(
  CURVE # Variable name
  "ALT_BN128" # Variable value
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
  OFF
)

option(
  WITH_PROCPS
  "Use procps for memory profiling"
  OFF
)

option(
  VERBOSE
  "Print internal messages"
  ON
)

option(
  DEBUG
  "Enable debugging mode"
  OFF
)

option(
  CPPDEBUG
  "Enable debugging of C++ STL (does not imply DEBUG)"
  ON
)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
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

# add_definitions() and remove_definitions() allow to modify the preprocessor settings
add_definitions(-DCURVE_${CURVE})

if(${CURVE} STREQUAL "BN128")
  add_definitions(-DBN_SUPPORT_SNARK=1)
endif()

if("${VERBOSE}")
  add_definitions(-DVERBOSE=1)
endif()

if("${MULTICORE}")
  add_definitions(-DMULTICORE=1)
endif()

add_definitions(-DDEBUG=1)

if("${CPPDEBUG}")
  add_definitions(-D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}")

include(FindPkgConfig)
if("${WITH_PROCPS}")
  pkg_check_modules(PROCPS REQUIRED libprocps)
else()
  add_definitions(-DNO_PROCPS)
endif()

# Add the given directories to those the compiler uses to search for include files
include_directories(.)

# Add sub-directories for the build
add_subdirectory(depends)
add_subdirectory(src)
