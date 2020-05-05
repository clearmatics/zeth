## Tests
if ("${IS_ZETH_PARENT}")
  include(CTest)

  # A target which builds all tests, even if they will not be run.
  add_custom_target(build_tests)

  # Function to create test targets, based on the FAST flag:
  #   zeth_test(
  #     <test name> SOURCE <source files> [ARGS <tst arguments>] [FAST])
  function(zeth_test TEST_NAME)
    set(multiValueArgs SOURCE ARGS)
    cmake_parse_arguments(zeth_test "FAST" "" "SOURCE;ARGS" ${ARGN})
    file(GLOB test_src ${zeth_test_SOURCE})

    # Test executable
    add_executable(${TEST_NAME} EXCLUDE_FROM_ALL ${test_src})
    target_link_libraries(
      ${TEST_NAME}
      zeth
      gtest_main ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})

    # Add all tests to the 'build_tests' target
    add_dependencies(build_tests ${TEST_NAME})

    if((NOT FAST_TESTS_ONLY) OR zeth_test_FAST)
      add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} ${zeth_test_ARGS})
      add_dependencies(check ${TEST_NAME})
    else()
      message("Skipping slow test ${TEST_NAME}")
    endif()
  endfunction(zeth_test)

  # TODO: Better convention for slow vs fast

  # All other tests are considered FAST
  file(
    GLOB_RECURSE
    TEST_SOURCE_FILES
    core/**_test.cpp
    snarks/${ZKSNARK_NAME}/**_test.cpp
    mpc/${ZKSNARK_NAME}/**_test.cpp
    circuits/**_test.cpp
    serialization/**_test.cpp
  )
  foreach(TEST_SOURCE ${TEST_SOURCE_FILES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    zeth_test(
      ${TEST_NAME}
      SOURCE ${TEST_SOURCE}
      ARGS "${CMAKE_CURRENT_LIST_DIR}/../.."
      FAST)
    message("Fast Test: ${TEST_NAME}")
  endforeach()

  # `prover` tests are considered SLOW
  file(GLOB_RECURSE TEST_SOURCE_FILES prover/**_test.cpp)
  foreach(TEST_SOURCE ${TEST_SOURCE_FILES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    zeth_test(${TEST_NAME} SOURCE ${TEST_SOURCE})
    # target_link_libraries(
    #   ${TEST_NAME} ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
    message("Slow Test: ${TEST_NAME}")
  endforeach()

  # zeth_test(test_bits SOURCE core/bits_test.cpp FAST)
  # zeth_test(test_field_element_utils SOURCE core/field_element_utils_test.cpp FAST)
  # zeth_test(test_group_element_utils SOURCE core/group_element_utils_test.cpp FAST)

  # zeth_test(test_hex_to_field SOURCE test/hex_to_field_test.cpp FAST)

  # zeth_test(test_addition SOURCE test/packed_addition_test.cpp FAST)
  # zeth_test(test_binary_operation SOURCE test/binary_operation_test.cpp FAST)
  # zeth_test(test_blake2s SOURCE test/blake2s_test.cpp FAST)
  # zeth_test(test_mimc_mp SOURCE test/mimc_mp_test.cpp FAST)
  # zeth_test(test_prfs SOURCE test/prfs_test.cpp FAST)
  # zeth_test(test_commitments SOURCE test/commitments_test.cpp FAST)
  # zeth_test(test_merkle_tree SOURCE test/merkle_tree_test.cpp FAST)
  # zeth_test(test_note SOURCE test/note_test.cpp FAST)
  # zeth_test(test_prover SOURCE test/prover_test.cpp)

  # Groth16 MPC tests
  if(${ZKSNARK_NAME} STREQUAL "groth16")
    # target_link_libraries(
    #   mpc_test ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
    # target_link_libraries(
    #   powersoftau_test ${Boost_FILESYSTEM_LIBRARY})

    # zeth_test(test_simple SOURCE test/simple_test.cpp FAST)
    # zeth_test(
    #   test_powersoftau
    #   SOURCE test/powersoftau_test.cpp
    #   ARGS "${CMAKE_CURRENT_LIST_DIR}/.."
    #   FAST)
    # zeth_test(test_mpc SOURCE test/mpc_*.cpp FAST)
    # target_link_libraries(
    #   test_mpc ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
    # target_link_libraries(
    #   test_powersoftau
    #   ${Boost_FILESYSTEM_LIBRARY}
    # )
  endif()

endif()
