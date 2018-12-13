include_directories(.)

file(GLOB_RECURSE SOURCES
    prover/computation.tcc
    prover/prover.tcc
    libsnark_helpers/libsnark_helpers.cpp
    sha256/sha256_ethereum.cpp
    sha256/sha256_ethereum.tcc
    cli/setupCmd.cpp
    cli/setupCmd.tcc
    cli/proveCmd.cpp
    cli/proveCmd.tcc
    cli/mainCmd.cpp
    cli/cli_utils.cpp
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
## Test for the prover
add_executable(
    prover_test
    EXCLUDE_FROM_ALL # Exclude this target from the default build target. Typing "make" will NOT cause this target to be built.

    test/prover_test.cpp
    ${SOURCES}
)
target_link_libraries(
    prover_test

    snark
)
target_include_directories(
    prover_test

    PUBLIC
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
include(CTest)
add_test(
    NAME prover_test
    COMMAND prover_test
)

# We add the test of the prover as part of the testzeth
add_dependencies(testzeth prover_test)
