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
    add_custom_target(
      cppcheck
      COMMAND cppcheck
      --project=${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
      --enable=all
      --suppress='*:${DEPENDS_DIR}/*'
      --suppress='*:${CMAKE_CURRENT_BINARY_DIR}/api/*'
      --suppressions-list=${PROJECT_SOURCE_DIR}/.cppcheck.suppressions
      --inline-suppr
      --quiet
      -i${DEPENDS_DIR}
      --error-exitcode=1
    )
  else()
      message(FATAL_ERROR "cppcheck not found. Aborting...")
  endif()
endif()
