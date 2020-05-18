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

# Adding clang-format target if executable is found
if(USE_CLANG_FORMAT)
  find_program(CLANG_FORMAT "clang-format")
  if(USE_CLANG_FORMAT)
    message("Using clang-format. Creating target... To run, use: make clang-format")
    add_custom_target(
      clang-format
      COMMAND git ls-files '*.cpp' '*.cc' '*.hpp' '*.hh' '*.tcc' | xargs ${CLANG_FORMAT} -style=file -i -verbose
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    )
  else()
    message(FATAL_ERROR "clang-format not found. Aborting...")
  endif()
endif()

# Adding clang-tidy target if executable is found
# The configuration below requires cmake 3.6.3+
# (https://cmake.org/cmake/help/v3.6/variable/CMAKE_LANG_CLANG_TIDY.html)
if(USE_CLANG_TIDY)
  find_program(CLANG_TIDY clang-tidy DOC "Path to clang-tidy tool")
  if(CLANG_TIDY)
    find_program(RUN_CLANG_TIDY run-clang-tidy.py DOC "Path to run-clang-tidy")
    if(RUN_CLANG_TIDY)
      message("Using clang-tidy. Creating target... To run, use: make clang-tidy")
      add_custom_target(
        clang-tidy
        COMMAND run-clang-tidy.py
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        )
      file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/api)
      file(WRITE ${PROJECT_BINARY_DIR}/api/.clang-tidy
        "Checks: '-*,misc-definitions-in-headers'
CheckOptions:
  - { key: HeaderFileExtensions,          value: \"x\" }")
    else()
      message(
        FATAL_ERROR
        "run-clang-tidy.py not found. (Download and place in PATH). Aborting...")
    endif()
  else()
    message(FATAL_ERROR "clang-tidy not found. Aborting...")
  endif()
endif()

# Adding "include-what-you-use" target if executable is found
# The configuration below requires cmake 3.3.2+
# (https://cmake.org/cmake/help/v3.3/variable/CMAKE_LANG_INCLUDE_WHAT_YOU_USE.html)
if(USE_IWYU)
  find_program(IWYU include-what-you-use DOC "Path to the include-what-you-use tool")
  if(USE_IWYU)
    message("Using include-what-you-use...")
    set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "${IWYU};-Xiwyu;")
  else()
    message(FATAL_ERROR "include-what-you-use not found. Aborting...")
  endif()
endif()
