# Run a set of GCC tools on the code base to maintain high code standards
# and catch potential security vulnerabilities
#
# Tools ran:
# - cppcheck

# Adding clang-format target if executable is found
find_program(CPP_CHECK "cppcheck")
if(CPP_CHECK)
  add_custom_target(
    cppcheck
    COMMAND cppcheck
    --project=compile_commands.json
    --enable=all
    --quiet
    -i${DEPENDS_DIR}
  )
endif()
