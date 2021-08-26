## Tests

include(CTest)

# A target which builds all tests, even if they will not be run.
add_custom_target(build_tests)

find_package(Boost REQUIRED COMPONENTS system filesystem)

# Function to create test targets, based on the FAST flag:
#
#   zeth_test(
#     <test name> SOURCE <source files> [ARGS <tst arguments>] [FAST])
function(zeth_test TEST_NAME)
  cmake_parse_arguments(zeth_test "FAST" "" "SOURCE;ARGS" ${ARGN})
  file(GLOB test_src ${zeth_test_SOURCE})

  message("TEST: ${TEST_NAME} ${zeth_test_SOURCE} (${zeth_test_FAST})")

  # Test executable
  add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${test_src})
  target_link_libraries(
    ${TEST_NAME}

    zeth
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    protobuf::libprotobuf
  )

  # Add all tests to the 'build_tests' target
  add_dependencies(build_tests ${TEST_NAME})

  if((NOT FAST_TESTS_ONLY) OR zeth_test_FAST)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} ${zeth_test_ARGS})
    add_dependencies(check ${TEST_NAME})
  else()
    message("Skipping slow test ${TEST_NAME}")
  endif()
endfunction(zeth_test)

# Function to process a list of test files, generating test names:
#
#   zeth_tests(SOURCES <sources> [ARGS <args>] [FAST])
function(zeth_tests)
  unset(fast)
  cmake_parse_arguments(zeth_tests "FAST" "" "SOURCES;ARGS" ${ARGN})
  if(zeth_tests_FAST)
    set(fast FAST)
  endif()
  foreach(TEST_SOURCE ${zeth_tests_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    zeth_test(
      ${TEST_NAME}
      SOURCE ${TEST_SOURCE}
      ARGS "${zeth_tests_ARGS}"
      ${fast}
    )
  endforeach()
endfunction(zeth_tests)

# Most tests are considered FAST
file(
  GLOB_RECURSE
  TEST_SOURCE_FILES
  core/**_test.cpp
  snarks/**_test.cpp
  mpc/**_test.cpp
  circuits/**_test.cpp
  serialization/**_test.cpp
)
zeth_tests(SOURCES ${TEST_SOURCE_FILES} ARGS "${CMAKE_CURRENT_LIST_DIR}/../.." FAST)

# `prover` tests are considered SLOW
file(GLOB_RECURSE TEST_SOURCE_FILES prover/**_test.cpp)
zeth_tests(SOURCES ${TEST_SOURCE_FILES} ARGS "${CMAKE_CURRENT_LIST_DIR}/../..")
