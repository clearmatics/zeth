# Run a set of LLVM/Clang tools on the code base to maintain high
# code standards and catch potential security vulnerabilities
#
# Tools ran:
# - clang-format
# - clang-tidy
# - include-what-you-use

# Get c++ files across all targets
file(
  GLOB_RECURSE
  ALL_SOURCE_FILES
  libzeth/**.?pp libzeth/**.tcc
  prover_server/**.?pp prover_server/**.tcc
  mpc_tools/**.?pp mpc_tools/**.tcc
)

# Adding clang-format target if executable is found
find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
  add_custom_target(
    clang-format
    COMMAND clang-format
    -style=file
    -i
    -verbose
    ${ALL_SOURCE_FILES}
  )
else()
  message(FATAL_ERROR "clang-format not found. Aborting...")
endif()

# Adding clang-tidy target if executable is found
# The configuration below requires cmake 3.6.3+
# (https://cmake.org/cmake/help/v3.6/variable/CMAKE_LANG_CLANG_TIDY.html)
find_program(CLANG_TIDY clang-tidy DOC "Path to the clang-tidy tool")
if(CLANG_TIDY)
  message("Using clang-tidy")
  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY};")
else()
  message("clang-tidy not found. Proceeding without it...")
endif()

# Adding "include-what-you-use" target if executable is found
# The configuration below requires cmake 3.3.2+
# (https://cmake.org/cmake/help/v3.3/variable/CMAKE_LANG_INCLUDE_WHAT_YOU_USE.html)
find_program(IWYU include-what-you-use DOC "Path to the include-what-you-use tool")
if(IWYU)
  message("Using include-what-you-use")
  set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "${IWYU};-Xiwyu;")
else()
  message("include-what-you-use not found. Proceeding without it...")
endif()
