# Runs code coverage tools

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(WARNING "Code coverage should not be used in non-debug mode"
    " (CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})")
endif()

find_program(GCOV gcov)
if(NOT GCOV)
  message(FATAL_ERROR "gcov not found. Aborting...")
endif()

set(
  COVERAGE_COMPILER_FLAGS
  "-g -fprofile-arcs -ftest-coverage"
  CACHE
  INTERNAL
  "Compiler flags for test coverage"
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COVERAGE_COMPILER_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COVERAGE_COMPILER_FLAGS}")

find_program(LCOV lcov)
if(NOT LCOV)
  message(FATAL_ERROR "lcov not found. Aborting...")
endif()

# See: https://wiki.documentfoundation.org/Development/Lcov#patch_.27geninfo.27
add_custom_target(
  raw_coverage
  COMMAND ${LCOV} --initial --directory ${PROJECT_SOURCE_DIR} --capture --output-file base_coverage.info
  COMMAND ${LCOV} --directory ${PROJECT_SOURCE_DIR} --capture --output-file test_coverage.info
  COMMAND ${LCOV} --add-tracefile base_coverage.info --add-tracefile test_coverage.info --output-file coverage.info
  COMMAND ${LCOV} --remove coverage.info /usr/\\*include/\\* ${PROJECT_SOURCE_DIR}/depends/\\* --output-file coverage.info
)

find_program(GENHTML genhtml)
if(NOT GENHTML)
  message(FATAL_ERROR "genhtml not found. Cannot export the tests"
    " coverages to HMTL. Please run 'raw_coverage' command instead.")
endif()

find_program(XDG_OPEN xdg-open)
if(NOT XDG_OPEN)
  set(XDG_OPEN cmake -E echo Test coverage report generated. Open )
endif()

add_custom_target(
  coverage
  COMMAND ${GENHTML} coverage.info --legend --title "Zeth code coverage report" --output-directory coverage_report
  COMMAND ${XDG_OPEN} coverage_report/index.html
  DEPENDS raw_coverage
)
