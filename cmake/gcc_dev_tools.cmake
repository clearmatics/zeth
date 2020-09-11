# Run a set of GCC tools on the code base to maintain high code standards
# and catch potential security vulnerabilities
#
# Tools ran:
# - cppcheck

option(
  USE_CPP_CHECK
  "Use cppcheck if the program is found."
  OFF
)

# Adding clang-format target if executable is found
if(USE_CPP_CHECK)
  find_program(CPP_CHECK "cppcheck")
  if(CPP_CHECK)
    message("cppcheck found!")
    message("Using cppcheck. Creating target... To run, use: make cppcheck")
    # TODO: gtest includes are not found by cppcheck, because they are marked
    # as "SYSTEM" (to prevent compile warnings). We exclude all tests for now,
    # to avoid many "syntaxError" reports, but the analysis should be run on
    # tests.
    add_custom_target(
      cppcheck
      COMMAND cppcheck
      --project=${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
      --enable=all
      --suppressions-list=${PROJECT_SOURCE_DIR}/.cppcheck.suppressions
      --inline-suppr
      --quiet
      -i${DEPENDS_DIR}
      --suppress='*:${DEPENDS_DIR}/*'
      -i${PROJECT_BINARY_DIR}/api
      --suppress='*:${PROJECT_BINARY_DIR}/api/*'
      --suppress='unmatchedSuppression:*'
      --error-exitcode=1
      --suppress='*:${PROJECT_SOURCE_DIR}/libzeth/tests/*'
    )
  else()
      message(FATAL_ERROR "cppcheck not found. Aborting...")
  endif()
endif()
