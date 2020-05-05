# Run a set of LLVM/Clang tools on the code base to maintain high
# code standards and catch potential security vulnerabilities
#
# Tools ran:
# - clang-format
# - clang-tidy
# - include-what-you-use

# Get c++ files across all targets
file(GLOB_RECURSE
  ALL_CXX_SOURCE_FILES
  libzeth/*.?pp
  prover_server/*.?pp
  mpc_tools/*.?pp
)

# Adding clang-format target if executable is found
find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
  add_custom_target(
    clang-format
    COMMAND clang-format
    -i
    -style=file
    ${ALL_CXX_SOURCE_FILES}
  )
else()
  message(FATAL_ERROR "clang-format not found. Aborting...")
endif()

# Adding clang-tidy target if executable is found
find_program(CLANG_TIDY "clang-tidy")
if(CLANG_TIDY)
  add_custom_target(
    clang-tidy
    COMMAND clang-tidy
    ${ALL_CXX_SOURCE_FILES}
    -p=${PROJECT_BINARY_DIR}
    -config=''
    --
    -std=c++11
  )
else()
  message(FATAL_ERROR "clang-tidy not found. Aborting...")
endif()

# Adding "include-what-you-use" target if executable is found
find_program(IWYU include-what-you-use DOC "Path to the include-what-you-use tool")
if(IWYU)
  message("Using include-what-you-use")
  set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "${IWYU};-Xiwyu;")
else()
    message("include-what-you-use not found. Proceeding without it...")
endif()
