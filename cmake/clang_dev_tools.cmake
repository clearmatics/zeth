# Run a set of LLVM/Clang tools on the code base to maintain high
# code standards and catch potential security vulnerabilities
#
# Tools ran:
# - clang-format
# - clang-tidy
# - include-what-you-use

option(
  USE_CLANG_FORMAT
  "Use clang-format if the program is found."
  OFF
)
option(
  USE_CLANG_TIDY
  "Use clang-tidy if the program is found."
  OFF
)
option(
  USE_IWYU
  "Use IWYU if the program is found."
  OFF
)

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
  message("clang-format found!")
    if(USE_CLANG_FORMAT)
      message("clang-format found. Creating target...")
      add_custom_target(
        clang-format
        COMMAND clang-format
        -style=file
        -i
        -verbose
        ${ALL_SOURCE_FILES}
      )
    endif()
else()
  message("clang-format not found. Proceeding without it...")
endif()

# Adding clang-tidy target if executable is found
# The configuration below requires cmake 3.6.3+
# (https://cmake.org/cmake/help/v3.6/variable/CMAKE_LANG_CLANG_TIDY.html)
find_program(CLANG_TIDY clang-tidy DOC "Path to the clang-tidy tool")
if(CLANG_TIDY)
  message("clang-tidy found!")
  if(USE_CLANG_TIDY)
    message("Using clang-tidy")
    set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY};")

    # Hack to avoid running clang-tidy on generated files (gRPC etc).
    # To do so, we generate a dummy .clang-tidy config file as done in:
    # https://gitlab.kitware.com/cmake/cmake/commit/b13bc8659f87567b1b091806d42f5023b2a6b48b
    file(WRITE "${PROJECT_BINARY_DIR}/.clang-tidy" "
    ---
    Checks: '-*,llvm-twine-local'
    ...
    ")
  endif()
else()
  message("clang-tidy not found. Proceeding without it...")
endif()

# Adding "include-what-you-use" target if executable is found
# The configuration below requires cmake 3.3.2+
# (https://cmake.org/cmake/help/v3.3/variable/CMAKE_LANG_INCLUDE_WHAT_YOU_USE.html)
find_program(IWYU include-what-you-use DOC "Path to the include-what-you-use tool")
if(IWYU)
  message("IWYU found!")
  if(USE_IWYU)
    message("Using include-what-you-use")
    set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "${IWYU};-Xiwyu;")
  endif()
else()
  message("include-what-you-use not found. Proceeding without it...")
endif()
