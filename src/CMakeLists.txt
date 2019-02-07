include_directories(
    $ENV{ZETH}
    $ENV{ZETH}/src
    $ENV{ZETH}/src/libsnark_helpers
    $ENV{ZETH}/src/circuits
    $ENV{ZETH}/src/sha256
    libff/common/default_types
)

file(GLOB_RECURSE SOURCES
    #circuits/computation.tcc
    #circuits/prover.tcc
    libsnark_helpers/libsnark_helpers.cpp
    libsnark_helpers/libsnark_helpers.tcc
    libsnark_helpers/extended_proof.tcc
    sha256/sha256_ethereum.cpp
    sha256/sha256_ethereum.tcc
    util.cpp
    #cli/setupCmd.cpp
    #cli/setupCmd.tcc
    #cli/proveCmd.cpp
    #cli/proveCmd.tcc
    #cli/mainCmd.cpp
    #cli/cli_utils.cpp
)

# Enable Boost for program_options
find_package( Boost REQUIRED COMPONENTS system filesystem )
include_directories( ${Boost_INCLUDE_DIR} )

# Add the binary tree to the search path for include files
# so that we will find zethConfig.h
include_directories("${PROJECT_BINARY_DIR}")

add_executable(
    zeth

    main.cpp
    ${SOURCES}
)

target_link_libraries(
    zeth

    LINK_PUBLIC # See: https://stackoverflow.com/questions/21125362/cmake-link-private-and-its-inheritance
    snark # Libsnark library
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)

target_include_directories(
    zeth

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

# Tests

## Test for the sha256 circuit
add_executable(
    test_sha256
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/sha256_test.cpp
    ${SOURCES}
    #${HEADER_FILES}
)
target_link_libraries(
    test_sha256

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_sha256

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_sha256
    COMMAND test_sha256
)

## Test for the prfs circuits
add_executable(
    test_prfs
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/prfs_test.cpp
    ${SOURCES}
    #${HEADER_FILES}
)
target_link_libraries(
    test_prfs

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_prfs

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_prfs
    COMMAND test_prfs
)

## Test for the commitments circuits
add_executable(
    test_commitments
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/commitments_test.cpp
    ${SOURCES}
    #${HEADER_FILES}
)
target_link_libraries(
    test_commitments

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_commitments

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_commitments
    COMMAND test_commitments
)

## Test for the note circuits
add_executable(
    test_note
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/note_test.cpp
    ${SOURCES}
    #${HEADER_FILES}
)
target_link_libraries(
    test_note

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_note

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_note
    COMMAND test_note
)

## Test for the JS circuit
add_executable(
    test_joinsplit
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/gadget_test.cpp
    ${SOURCES}
    #${HEADER_FILES}
)
target_link_libraries(
    test_joinsplit

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_joinsplit

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_joinsplit
    COMMAND test_joinsplit
)

## Test for the note debug circuits
add_executable(
    test_debug
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/note_debug_test.cpp
    ${SOURCES}
    #${HEADER_FILES}
)
target_link_libraries(
    test_debug

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_debug

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_debug
    COMMAND test_debug
)

## Test for the packed_addition
add_executable(
    test_packed
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/packed_addition_test.cpp
    ${SOURCES}
    #${HEADER_FILES}
)
target_link_libraries(
    test_packed

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_packed

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_packed
    COMMAND test_packed
)

## Test for the full_prover
add_executable(
    test_full
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/full_prover_test.cpp
    ${SOURCES}
)
target_link_libraries(
    test_full

    snark
    gtest_main
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
)
target_include_directories(
    test_full

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME test_full
    COMMAND test_full
)

# We add the test of the prover as part of the testzeth
add_dependencies(testzeth test_prfs)
add_dependencies(testzeth test_commitments)
